"""
1id.com -- Identity Router

Public identity lookup endpoints:
  GET /api/v1/identity/{agent_id}   -- look up basic identity info
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from services import identity_service, handle_service

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


@router.get("/{agent_id}")
async def get_identity_public_info(agent_id: str):
  """
  Public identity lookup. Anyone can look up basic identity info.

  No private information. No activity log. No list of services used.
  This is the only data we expose about an identity -- exactly what's
  in the JWT anyway.
  """
  identity = identity_service.get_identity_by_internal_id(agent_id)

  if identity is None:
    return JSONResponse(
      status_code=404,
      content={
        "ok": False,
        "data": None,
        "error": {
          "code": "IDENTITY_NOT_FOUND",
          "message": f"No identity found with ID '{agent_id}'",
        },
      },
    )

  display_handle = handle_service.get_display_handle_for_identity(agent_id)

  registered_at = identity["registered_at"]
  if hasattr(registered_at, "isoformat"):
    registered_at = registered_at.isoformat() + "Z"

  return JSONResponse(
    status_code=200,
    content={
      "ok": True,
      "data": {
        "internal_id": identity["internal_id"],
        "handle": display_handle,
        "trust_tier": identity["trust_tier"],
        "tpm_manufacturer": None,  # TODO: look up from ek_registry
        "registered_at": str(registered_at),
        "status": identity["status"],
      },
      "error": None,
    },
  )
