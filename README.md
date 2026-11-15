# TOTP 2FA with Microsoft Authenticator: Spring Boot demo

No API key and no Microsoft account are needed. This uses standard TOTP (RFC 6238).

## Run

```bash
mvn spring-boot:run
```

Open http://localhost:8080 and:

1. Register a user and log in.
2. Click **Set up 2FA**. In Microsoft Authenticator, tap **+**, choose **Other account (Google, Facebook, etc.)**, and scan the QR code.
3. Enter the 6-digit code to turn 2FA on. Save the recovery codes.
4. Log out and log in again. After the password step you will be asked for the code.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | /api/auth/register | public | `{username, password}` |
| POST | /api/auth/login | public | `{username, password}`; returns `mfaRequired` |
| POST | /api/auth/login/verify | pre-auth session | `{code}`: TOTP or recovery code |
| GET | /api/me | logged in | account status |
| POST | /api/2fa/setup | logged in | new secret and QR code |
| POST | /api/2fa/enable | logged in | `{code}`: turns 2FA on and returns recovery codes |
| POST | /api/2fa/disable | logged in | `{code}` |
| POST | /api/logout | logged in | |

## Before production

- Set `APP_TOTP_ENCRYPTION_KEY` (`openssl rand -base64 32`) and never commit it.
- Turn CSRF protection back on in `SecurityConfig`.
- Use HTTPS only.
- Add rate limiting per IP and per account on `/api/auth/login` and `/api/auth/login/verify` (for example, Bucket4j).
- Replace H2 with your real database.
