"""
1id.com -- Handle Router

Handle management endpoints:
  GET  /api/v1/handle/{name}     -- check handle availability
  POST /api/v1/handle/register   -- register a handle (requires auth)
  DELETE /api/v1/handle/{name}   -- cancel a handle permanently
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from services import handle_service

router = APIRouter(prefix="/api/v1/handle", tags=["handles"])


@router.get("/{name}")
async def check_handle_availability(name: str):
  """
  Check handle availability. Public endpoint, no auth required.
  Returns: available, taken, dormant, or retired.
  """
  handle_name = name.lower().lstrip("@")

  is_valid, error_message = handle_service.validate_handle_name(handle_name)
  if not is_valid:
    return JSONResponse(
      status_code=400,
      content={
        "ok": False,
        "data": None,
        "error": {"code": "HANDLE_INVALID", "message": error_message},
      },
    )

  status = handle_service.check_handle_availability(handle_name)
  pricing_tier = handle_service.classify_handle_pricing_tier(handle_name)

  return JSONResponse(
    status_code=200,
    content={
      "ok": True,
      "data": {
        "handle": f"@{handle_name}",
        "status": status,
        "pricing_tier": pricing_tier,
      },
      "error": None,
    },
  )
