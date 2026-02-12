"""
1id.com Enrollment API

Hardware-anchored identity enrollment for AI agents.
Port 8180 -- see /ports.md for registry.

Endpoints:
  /api/health                        -- health check
  /api/v1/status                     -- API status and capabilities
  /api/v1/enroll/declared            -- declared-tier enrollment (no TPM)
  /api/v1/enroll/begin               -- begin sovereign enrollment (TPM)
  /api/v1/enroll/activate            -- complete sovereign enrollment
  /api/v1/identity/{agent_id}        -- public identity lookup
  /api/v1/handle/{name}              -- check handle availability
  /api/docs                          -- Swagger UI documentation

Run with:
    uvicorn app:app --host 127.0.0.1 --port 8180
"""

import datetime
import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import config
from routers import enroll, identity, handle

# --- Logging ---
logging.basicConfig(
  level=logging.INFO,
  format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("oneid.api")

# --- FastAPI app ---
app = FastAPI(
  title="1id.com Enrollment API",
  description="Hardware-anchored identity enrollment for AI agents. "
              "Passport Office for AI: unique, verifiable, hardware-backed identities.",
  version=config.API_VERSION,
  docs_url="/api/docs",
  redoc_url="/api/redoc",
  openapi_url="/api/openapi.json",
)

# --- Register routers ---
app.include_router(enroll.router)
app.include_router(identity.router)
app.include_router(handle.router)


# --- Health and status ---

class HealthResponse(BaseModel):
  status: str
  service: str
  version: str
  timestamp: str
  database: str


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
  """Health check endpoint for monitoring and load balancers."""
  db_status = "unknown"
  try:
    import database
    row = database.execute_query_returning_one_row("SELECT 1 AS alive")
    if row and row.get("alive") == 1:
      db_status = "connected"
    else:
      db_status = "error"
  except Exception as db_error:
    db_status = f"error: {db_error}"

  return HealthResponse(
    status="healthy",
    service="1id-enrollment-api",
    version=config.API_VERSION,
    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    database=db_status,
  )


@app.get("/api/v1/status")
async def api_status():
  """API status and capabilities."""
  return JSONResponse(
    content={
      "ok": True,
      "data": {
        "status": "operational",
        "version": config.API_VERSION,
        "capabilities": [
          "health-check",
          "enroll-declared",
          "enroll-sovereign-begin",
          "enroll-sovereign-activate",
          "identity-lookup",
          "handle-availability",
        ],
        "endpoints": {
          "health": "/api/health",
          "enroll_declared": "/api/v1/enroll/declared",
          "enroll_begin": "/api/v1/enroll/begin",
          "enroll_activate": "/api/v1/enroll/activate",
          "identity_lookup": "/api/v1/identity/{agent_id}",
          "handle_check": "/api/v1/handle/{name}",
          "docs": "/api/docs",
        },
      },
      "error": None,
    }
  )


@app.get("/api/")
async def api_root():
  """API root -- discovery."""
  return JSONResponse(
    content={
      "ok": True,
      "data": {
        "message": "1id.com Enrollment API -- Passport Office for AI Agents",
        "docs": "/api/docs",
        "health": "/api/health",
        "status": "/api/v1/status",
      },
      "error": None,
    }
  )


if __name__ == "__main__":
  import uvicorn
  logger.info("Starting 1id.com Enrollment API on %s:%d", config.API_HOST, config.API_PORT)
  uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
