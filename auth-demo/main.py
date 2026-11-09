"""Passwordless signup/login demo. Email codes, 24-hour accounts. Run: uvicorn main:app --reload"""
import asyncio, hashlib, hmac, logging, os, re, secrets, time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from sqlalchemy import create_engine, text

SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
for old in ("postgres://", "postgresql://"):
    if DB_URL.startswith(old):
        DB_URL = DB_URL.replace(old, "postgresql+psycopg://", 1)
RATE = int(os.getenv("RATE_LIMIT", "8"))
ACCOUNT_TTL, OTP_TTL, SESSION_TTL, MAX_ATTEMPTS, COOKIE = 24 * 3600, 300, 3600, 5, "session"
BAD_CODE = "That code is wrong or has expired. Request a new one."
engine = create_engine(DB_URL, pool_pre_ping=True)

SCHEMA = [
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT UNIQUE NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS otps (email TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at BIGINT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (email, purpose))",
    "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL)",
]


def now() -> int:
    return int(time.time())


def digest(value: str) -> str:
    return hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def init_db():
    with engine.begin() as c:
        for stmt in SCHEMA:
            c.execute(text(stmt))


def purge():
    """Delete expired accounts and everything attached to them."""
    t = now()
    with engine.begin() as c:
        c.execute(text("DELETE FROM sessions WHERE expires_at<:t OR user_id IN (SELECT id FROM users WHERE expires_at<:t)"), {"t": t})
        c.execute(text("DELETE FROM otps WHERE expires_at<:t OR email IN (SELECT email FROM users WHERE expires_at<:t)"), {"t": t})
        c.execute(text("DELETE FROM users WHERE expires_at<:t"), {"t": t})


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()

    async def loop():
        while True:
            try:
                await asyncio.to_thread(purge)
            except Exception:
                logging.exception("purge failed")
            await asyncio.sleep(600)

    task = asyncio.create_task(loop())
    yield
    task.cancel()


app = FastAPI(title="Auth demo", lifespan=lifespan)
HITS: dict[str, deque] = defaultdict(deque)


def limit(key: str, n: int = RATE, per: int = 60):
    q, t = HITS[key], time.time()
    while q and q[0] < t - per:
        q.popleft()
    if len(q) >= n:
        raise HTTPException(429, "Too many requests. Wait a minute and try again.")
    q.append(t)


def ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def send_code(email: str, code: str, purpose: str):
    key = os.getenv("RESEND_API_KEY")
    if not key:
        logging.warning("DEV MODE (no email key): code for %s is %s", email, code)
        return
    try:
        httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {key}"},
            json={"from": os.getenv("MAIL_FROM", "onboarding@resend.dev"), "to": [email],
                  "subject": "Your verification code", "text": f"Your code is {code}. It expires in 5 minutes."},
            timeout=10,
        )
    except Exception:
        logging.exception("email send failed")


def issue_otp(email: str, purpose: str):
    code = f"{secrets.randbelow(10**6):06d}"
    with engine.begin() as c:
        c.execute(text("DELETE FROM otps WHERE email=:e AND purpose=:p"), {"e": email, "p": purpose})
        c.execute(text("INSERT INTO otps (email,purpose,code_hash,expires_at,attempts) VALUES (:e,:p,:h,:x,0)"),
                  {"e": email, "p": purpose, "h": digest(code), "x": now() + OTP_TTL})
    send_code(email, code, purpose)


def check_otp(email: str, purpose: str, code: str):
    ok = False
    with engine.begin() as c:
        row = c.execute(text("SELECT code_hash,expires_at,attempts FROM otps WHERE email=:e AND purpose=:p"), {"e": email, "p": purpose}).first()
        if row and row.expires_at >= now() and row.attempts < MAX_ATTEMPTS:
            if hmac.compare_digest(row.code_hash, digest(code)):
                ok = True
                c.execute(text("DELETE FROM otps WHERE email=:e AND purpose=:p"), {"e": email, "p": purpose})
            else:
                c.execute(text("UPDATE otps SET attempts=attempts+1 WHERE email=:e AND purpose=:p"), {"e": email, "p": purpose})
    if not ok:
        raise HTTPException(400, BAD_CODE)


def start_session(response: Response, user_id: str, user_expires: int):
    token = secrets.token_urlsafe(32)
    exp = min(now() + SESSION_TTL, user_expires)
    with engine.begin() as c:
        c.execute(text("INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (:h,:u,:x)"), {"h": digest(token), "u": user_id, "x": exp})
    response.set_cookie(COOKIE, token, httponly=True, secure=os.getenv("COOKIE_SECURE", "1") == "1", samesite="lax", max_age=exp - now())


def current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if token:
        with engine.begin() as c:
            row = c.execute(text("SELECT u.id,u.first_name,u.last_name,u.phone,u.email,u.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=:h AND s.expires_at>:t AND u.expires_at>:t"),
                            {"h": digest(token), "t": now()}).mappings().first()
        if row:
            return dict(row)
    raise HTTPException(401, "Not signed in")


NAME = re.compile(r"^[^\W\d_]+(?:[ '\-][^\W\d_]+)*$")


class Register(BaseModel):
    first_name: str
    last_name: str
    phone: str
    email: EmailStr
    email_confirm: EmailStr

    @field_validator("first_name", "last_name")
    @classmethod
    def valid_name(cls, v: str) -> str:
        v = v.strip()
        if not (1 <= len(v) <= 50 and NAME.match(v)):
            raise ValueError("Names can only contain letters, spaces, hyphens and apostrophes")
        return v

    @field_validator("phone")
    @classmethod
    def valid_phone(cls, v: str) -> str:
        v = re.sub(r"[ \-()]", "", v)
        if not re.fullmatch(r"\+[1-9]\d{7,14}", v):
            raise ValueError("Use international format, for example +639171234567")
        return v

    @model_validator(mode="after")
    def emails_match(self):
        if self.email.lower() != self.email_confirm.lower():
            raise ValueError("The two email addresses do not match")
        return self


class EmailIn(BaseModel):
    email: EmailStr


class CodeIn(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")


GENERIC = {"message": "If this email can be used, a 6-digit code was sent."}


@app.post("/api/register")
def register(d: Register, request: Request):
    limit(f"reg:{ip(request)}")
    email, t = d.email.lower(), now()
    send = True
    with engine.begin() as c:
        row = c.execute(text("SELECT verified FROM users WHERE email=:e"), {"e": email}).first()
        if row is None:
            c.execute(text("INSERT INTO users (id,first_name,last_name,phone,email,verified,created_at,expires_at) VALUES (:i,:f,:l,:p,:e,0,:c,:x)"),
                      {"i": secrets.token_hex(16), "f": d.first_name, "l": d.last_name, "p": d.phone, "e": email, "c": t, "x": t + ACCOUNT_TTL})
        elif not row.verified:
            c.execute(text("UPDATE users SET first_name=:f,last_name=:l,phone=:p WHERE email=:e"), {"f": d.first_name, "l": d.last_name, "p": d.phone, "e": email})
        else:
            send = False
    if send:
        issue_otp(email, "verify")
    return GENERIC


@app.post("/api/verify")
def verify(d: CodeIn, request: Request, response: Response):
    limit(f"ver:{ip(request)}", RATE * 3)
    email = d.email.lower()
    check_otp(email, "verify", d.code)
    with engine.begin() as c:
        c.execute(text("UPDATE users SET verified=1 WHERE email=:e"), {"e": email})
        u = c.execute(text("SELECT id,expires_at FROM users WHERE email=:e AND expires_at>:t"), {"e": email, "t": now()}).first()
    if not u:
        raise HTTPException(400, BAD_CODE)
    start_session(response, u.id, u.expires_at)
    return {"ok": True}


@app.post("/api/login")
def login(d: EmailIn, request: Request):
    limit(f"log:{ip(request)}")
    purge()
    email = d.email.lower()
    with engine.begin() as c:
        row = c.execute(text("SELECT verified,expires_at FROM users WHERE email=:e"), {"e": email}).first()
    if row and row.verified and row.expires_at > now():
        issue_otp(email, "login")
    return GENERIC


@app.post("/api/login/verify")
def login_verify(d: CodeIn, request: Request, response: Response):
    limit(f"lver:{ip(request)}", RATE * 3)
    email = d.email.lower()
    check_otp(email, "login", d.code)
    with engine.begin() as c:
        u = c.execute(text("SELECT id,expires_at FROM users WHERE email=:e AND verified=1 AND expires_at>:t"), {"e": email, "t": now()}).first()
    if not u:
        raise HTTPException(400, BAD_CODE)
    start_session(response, u.id, u.expires_at)
    return {"ok": True}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return {**user, "seconds_left": max(0, user["expires_at"] - now())}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with engine.begin() as c:
            c.execute(text("DELETE FROM sessions WHERE token_hash=:h"), {"h": digest(token)})
    response.delete_cookie(COOKIE)
    return {"ok": True}


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
