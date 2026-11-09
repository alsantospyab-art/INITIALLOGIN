# Auth demo (FastAPI)

Passwordless registration and login with email codes, a dashboard with logout, and accounts that delete themselves 24 hours after creation.

## Run locally
    pip install -r requirements.txt
    pytest
    uvicorn main:app --reload      # http://localhost:8000
Without `RESEND_API_KEY`, codes are printed in the server log (dev mode only).

## Environment variables
| Name | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string (defaults to a local SQLite file) |
| `SECRET_KEY` | Long random string used to hash codes and sessions (required in production) |
| `RESEND_API_KEY`, `MAIL_FROM` | Email provider key and sender address |
| `COOKIE_SECURE` | Keep `1` in production (HTTPS) |

## Security notes
Codes and session tokens are stored hashed, codes expire in 5 minutes and lock after 5 wrong tries, requests are rate limited, cookies are HttpOnly and SameSite, responses do not reveal whether an email exists, and all input is validated on the server.
Some email providers only deliver to your own address until you verify a sending domain. Check your provider's rules.
