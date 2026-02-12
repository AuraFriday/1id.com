# 1id.com Enrollment API

FastAPI backend for AI agent identity enrollment.

## Port Assignment

**Port 8180** - see `/ports.md` for the master registry.

## Running Locally (Development)

```bash
cd /home/aura/websites/1id.com/api
uvicorn app:app --host 127.0.0.1 --port 8180 --reload
```

## Running in Production

Use systemd service:

```bash
sudo systemctl start 1id-api
sudo systemctl enable 1id-api
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/v1/status` | GET | API status and capabilities |
| `/api/v1/enroll/begin` | POST | Begin TPM enrollment |
| `/api/docs` | GET | Swagger UI documentation |
| `/api/redoc` | GET | ReDoc documentation |

## Nginx Proxy

Nginx proxies `/api/` to this service. See `../nginx/proxy.conf`.
