# NovaTech Solutions — Auth Testing Site

A realistic enterprise authentication testing website built with React (CDN), no build step required.

## Features
- Sign in with email + password
- Multi-factor authentication (TOTP / SMS)
- Forgot password flow
- Account recovery codes
- Two-step registration with password strength meter
- Dashboard with session management
- Security settings panel

## Test Credentials
| Field | Value |
|---|---|
| Email | `demo@novatech.io` |
| Password | `Demo@1234` |
| MFA Code | `123456` |
| Recovery Code | `NOVA-TECH-2024-ABCD` |

## Deploy
This is a static single-file app. Deploy anywhere that serves HTML.

### Vercel
```bash
npx vercel --prod
```

### Local
Just open `index.html` in a browser.

### Local firewall-demo server

From the project root on the server PC:

```powershell
python scripts/serve_test_site.py --host 0.0.0.0 --port 8080
```

Client PCs open:

```text
http://SERVER_IP:8080
```

On each client PC, run:

```powershell
python scripts/client_logger.py --server-api http://SERVER_IP:8001/api/events --test-site-host SERVER_IP --test-site-port 8080 --client-id client1
```

Approving an AI firewall recommendation blocks that client IP from accessing
this site on the server PC.
