"""
1id.com -- Enrollment Router

Handles all enrollment endpoints:
  POST /api/v1/enroll/declared   -- declared-tier (no TPM)
  POST /api/v1/enroll/begin      -- start sovereign enrollment
  POST /api/v1/enroll/activate   -- complete sovereign enrollment
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import logging

from models import (
  DeclaredEnrollmentRequest,
  SovereignEnrollmentBeginRequest,
  EnrollmentActivateRequest,
)
from services import (
  identity_service,
  handle_service,
  keycloak_service,
  ek_service,
  enrollment_session_service,
)
import config

logger = logging.getLogger("oneid.enroll")

router = APIRouter(prefix="/api/v1/enroll", tags=["enrollment"])

# -- In-memory rate limiter for declared tier --
# Uses a simple dict keyed by IP address. Resets on server restart,
# which is acceptable since the main purpose is slowing down bots.
# For production hardening, migrate to Redis or MySQL-backed storage.
import time
from collections import defaultdict

_declared_enrollment_attempts_by_ip = defaultdict(list)


def _check_declared_tier_rate_limit(client_ip: str) -> tuple[bool, str]:
  """Check if the IP has exceeded the declared-tier enrollment rate limit.

  Returns (allowed, error_message).
  """
  now = time.time()
  one_hour_ago = now - 3600
  one_day_ago = now - 86400

  # Clean old entries
  attempts = _declared_enrollment_attempts_by_ip[client_ip]
  _declared_enrollment_attempts_by_ip[client_ip] = [
    t for t in attempts if t > one_day_ago
  ]
  attempts = _declared_enrollment_attempts_by_ip[client_ip]

  # Count recent attempts
  attempts_last_hour = sum(1 for t in attempts if t > one_hour_ago)
  attempts_last_day = len(attempts)

  if attempts_last_hour >= config.DECLARED_TIER_MAX_ENROLLMENTS_PER_IP_PER_HOUR:
    return False, (
      f"Rate limit exceeded: max {config.DECLARED_TIER_MAX_ENROLLMENTS_PER_IP_PER_HOUR} "
      f"declared enrollments per IP per hour. Try again later."
    )

  if attempts_last_day >= config.DECLARED_TIER_MAX_ENROLLMENTS_PER_IP_PER_DAY:
    return False, (
      f"Rate limit exceeded: max {config.DECLARED_TIER_MAX_ENROLLMENTS_PER_IP_PER_DAY} "
      f"declared enrollments per IP per day. Try again tomorrow."
    )

  return True, ""


def _record_declared_tier_enrollment(client_ip: str):
  """Record a successful declared-tier enrollment for rate limiting."""
  _declared_enrollment_attempts_by_ip[client_ip].append(time.time())


def _make_error_response(http_status_code, error_code, error_message):
  """Build a standard error envelope."""
  return JSONResponse(
    status_code=http_status_code,
    content={
      "ok": False,
      "data": None,
      "error": {"code": error_code, "message": error_message},
    },
  )


def _make_success_response(data, http_status_code=200):
  """Build a standard success envelope."""
  return JSONResponse(
    status_code=http_status_code,
    content={"ok": True, "data": data, "error": None},
  )


# =====================================================================
# POST /api/v1/enroll/declared
# =====================================================================

@router.post("/declared")
async def enroll_declared_tier(
  request_body: DeclaredEnrollmentRequest,
  request: Request,
):
  """
  Declared-tier enrollment: no TPM required, lowest trust level.
  Rate-limited aggressively (this is the Sybil-vulnerable path).
  """
  # Use X-Forwarded-For if behind nginx, otherwise client IP directly.
  # nginx is configured with proxy_set_header X-Forwarded-For $remote_addr
  forwarded_for = request.headers.get("x-forwarded-for")
  client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else request.client.host
  logger.info(
    "Declared enrollment request from %s (handle=%s)",
    client_ip,
    request_body.requested_handle,
  )

  # --- Rate limit check ---
  rate_limit_allowed, rate_limit_error = _check_declared_tier_rate_limit(client_ip)
  if not rate_limit_allowed:
    logger.warning("Rate limit hit for %s: %s", client_ip, rate_limit_error)
    return _make_error_response(429, "RATE_LIMIT_EXCEEDED", rate_limit_error)

  # --- Handle validation (if requested) ---
  handle_name_to_register = None
  if request_body.requested_handle:
    handle_name = request_body.requested_handle.lower().lstrip("@")

    is_valid_handle, handle_error_message = handle_service.validate_handle_name(handle_name)
    if not is_valid_handle:
      return _make_error_response(400, "HANDLE_INVALID", handle_error_message)

    availability = handle_service.check_handle_availability(handle_name)
    if availability == "taken" or availability == "active":
      return _make_error_response(409, "HANDLE_TAKEN", f"Handle '@{handle_name}' is already in use")
    if availability == "retired":
      return _make_error_response(410, "HANDLE_RETIRED", f"Handle '@{handle_name}' has been permanently retired")
    if availability == "dormant":
      return _make_error_response(409, "HANDLE_TAKEN", f"Handle '@{handle_name}' is reserved (dormant)")

    handle_name_to_register = handle_name

  # --- Generate internal ID ---
  internal_id = identity_service.generate_unique_internal_id()

  # --- Create Keycloak client ---
  try:
    keycloak_credentials = await keycloak_service.create_confidential_client_for_agent(
      agent_internal_id=internal_id,
    )
  except Exception as keycloak_error:
    logger.error("Keycloak client creation failed: %s", keycloak_error)
    return _make_error_response(
      500,
      "KEYCLOAK_ERROR",
      f"Failed to create agent credentials: {keycloak_error}",
    )

  # --- Insert identity into database ---
  identity_service.create_declared_tier_identity(
    internal_id=internal_id,
    keycloak_client_id=keycloak_credentials["client_id"],
    operator_email=request_body.operator_email,
  )

  # --- Register handle (if requested) ---
  display_handle = f"@{internal_id}"
  if handle_name_to_register:
    handle_service.register_handle_for_identity(handle_name_to_register, internal_id)
    display_handle = f"@{handle_name_to_register}"

  # --- Get initial tokens ---
  initial_tokens = None
  try:
    token_response = await keycloak_service.get_initial_tokens_for_agent(
      client_id=keycloak_credentials["client_id"],
      client_secret=keycloak_credentials["client_secret"],
    )
    initial_tokens = {
      "access_token": token_response["access_token"],
      "refresh_token": token_response.get("refresh_token"),
      "expires_in": token_response.get("expires_in", 3600),
      "token_type": "Bearer",
    }
  except Exception as token_error:
    logger.warning(
      "Could not fetch initial tokens for %s (Keycloak may not have agents realm yet): %s",
      internal_id,
      token_error,
    )
    # Non-fatal: agent can use client_id/client_secret to get tokens later

  # --- Record enrollment for rate limiting ---
  _record_declared_tier_enrollment(client_ip)

  logger.info(
    "Declared enrollment complete: id=%s, handle=%s",
    internal_id,
    display_handle,
  )

  # Fetch the actual registered_at timestamp from the database
  from datetime import datetime, timezone
  identity_db_row = identity_service.get_identity_by_internal_id(internal_id)
  registered_at_value = None
  if identity_db_row and identity_db_row.get("registered_at"):
    registered_at_value = identity_db_row["registered_at"].isoformat() + "Z"
  else:
    registered_at_value = datetime.now(timezone.utc).isoformat()

  return _make_success_response(
    {
      "identity": {
        "internal_id": internal_id,
        "handle": display_handle,
        "trust_tier": "declared",
        "tpm_manufacturer": None,
        "registered_at": registered_at_value,
      },
      "credentials": {
        "client_id": keycloak_credentials["client_id"],
        "client_secret": keycloak_credentials["client_secret"],
        "token_endpoint": config.TOKEN_ENDPOINT,
        "grant_type": "client_credentials",
      },
      "initial_tokens": initial_tokens,
    },
    http_status_code=201,
  )


# =====================================================================
# POST /api/v1/enroll/begin
# =====================================================================

@router.post("/begin")
async def enroll_sovereign_begin(
  request_body: SovereignEnrollmentBeginRequest,
  request: Request,
):
  """
  Begin TPM-based enrollment (sovereign/virtual tier).
  Validates EK cert, checks anti-Sybil registry, returns credential challenge.
  """
  logger.info(
    "Sovereign enrollment begin from %s",
    request.client.host,
  )

  # --- Validate EK certificate and chain ---
  is_valid_ek, trust_tier, manufacturer_code, ek_error = \
    ek_service.validate_ek_certificate_chain(
      request_body.ek_certificate_pem,
      request_body.ek_certificate_chain_pem,
    )

  if not is_valid_ek:
    error_code = "EK_CERT_INVALID" if "parse" in (ek_error or "").lower() else "EK_CERT_CHAIN_UNTRUSTED"
    return _make_error_response(400, error_code, ek_error)

  # --- Anti-Sybil check: is this EK already registered? ---
  ek_fingerprint = ek_service.compute_ek_fingerprint_sha256(request_body.ek_certificate_pem)
  existing_identity = ek_service.check_ek_fingerprint_already_registered(ek_fingerprint)

  if existing_identity:
    return _make_error_response(
      409,
      "EK_ALREADY_REGISTERED",
      f"This TPM endorsement key is already associated with identity {existing_identity}",
    )

  # --- Handle pre-check (if requested) ---
  handle_status_info = None
  if request_body.requested_handle:
    handle_name = request_body.requested_handle.lower().lstrip("@")
    is_valid_handle, handle_error = handle_service.validate_handle_name(handle_name)
    if not is_valid_handle:
      return _make_error_response(400, "HANDLE_INVALID", handle_error)

    availability = handle_service.check_handle_availability(handle_name)
    if availability == "taken" or availability == "active":
      return _make_error_response(409, "HANDLE_TAKEN", f"Handle '@{handle_name}' is already in use")
    if availability == "retired":
      return _make_error_response(410, "HANDLE_RETIRED", f"Handle '@{handle_name}' has been permanently retired")

    handle_status_info = {
      "handle_status": "available",
      "handle_pricing_tier": handle_service.classify_handle_pricing_tier(handle_name),
    }

  # --- Generate credential activation challenge ---
  # TODO: Implement real TPM2_MakeCredential using the EK public key
  # For now, use a symmetric challenge (the credential is the challenge itself)
  challenge_bytes, challenge_base64 = enrollment_session_service.generate_credential_challenge()

  # The "expected credential" is what we expect back after TPM2_ActivateCredential.
  # In the real implementation, this is derived from MakeCredential.
  # For now, the expected credential IS the challenge (symmetric proof).
  expected_credential_bytes = challenge_bytes

  # --- Create enrollment session ---
  session_id = enrollment_session_service.create_enrollment_session(
    ek_fingerprint_sha256=ek_fingerprint,
    ak_public_key_pem=request_body.ak_public_key_pem,
    credential_challenge_bytes=challenge_bytes,
    expected_credential_bytes=expected_credential_bytes,
    trust_tier=trust_tier,
    tpm_manufacturer_code=manufacturer_code,
    requested_handle=request_body.requested_handle,
    operator_email=request_body.operator_email,
  )

  response_data = {
    "enrollment_session_id": session_id,
    "credential_activation_challenge": challenge_base64,
    "trust_tier": trust_tier,
    "tpm_manufacturer": manufacturer_code,
    "expires_in_seconds": config.ENROLLMENT_SESSION_TTL_SECONDS,
  }

  if handle_status_info:
    response_data.update(handle_status_info)

  logger.info(
    "Enrollment session created: session=%s, tier=%s, manufacturer=%s",
    session_id, trust_tier, manufacturer_code,
  )

  return _make_success_response(response_data)


# =====================================================================
# POST /api/v1/enroll/activate
# =====================================================================

@router.post("/activate")
async def enroll_sovereign_activate(
  request_body: EnrollmentActivateRequest,
  request: Request,
):
  """
  Complete sovereign enrollment by verifying the decrypted credential.
  Creates identity, registers EK, creates Keycloak client, issues tokens.
  """
  import base64

  logger.info(
    "Enrollment activate: session=%s",
    request_body.enrollment_session_id,
  )

  # --- Look up session ---
  session = enrollment_session_service.get_enrollment_session(
    request_body.enrollment_session_id
  )
  if session is None:
    return _make_error_response(
      404,
      "SESSION_NOT_FOUND",
      "Enrollment session not found, expired, or already completed",
    )

  # --- Verify decrypted credential ---
  try:
    submitted_credential = base64.b64decode(request_body.decrypted_credential)
  except Exception:
    return _make_error_response(400, "INVALID_CREDENTIAL", "decrypted_credential is not valid base64")

  expected_credential = bytes(session["expected_credential"])
  if submitted_credential != expected_credential:
    return _make_error_response(
      403,
      "CREDENTIAL_MISMATCH",
      "Decrypted credential does not match the expected value. "
      "TPM possession could not be verified.",
    )

  # --- All checks passed: create the identity ---
  internal_id = identity_service.generate_unique_internal_id()
  trust_tier = session["trust_tier"]
  manufacturer_code = session["tpm_manufacturer_code"]

  # Create Keycloak client
  try:
    keycloak_credentials = await keycloak_service.create_confidential_client_for_agent(
      agent_internal_id=internal_id,
    )
  except Exception as keycloak_error:
    logger.error("Keycloak client creation failed: %s", keycloak_error)
    return _make_error_response(
      500,
      "KEYCLOAK_ERROR",
      f"Failed to create agent credentials: {keycloak_error}",
    )

  # Insert identity
  identity_service.create_sovereign_tier_identity(
    internal_id=internal_id,
    trust_tier=trust_tier,
    keycloak_client_id=keycloak_credentials["client_id"],
    operator_email=session.get("operator_email"),
  )

  # Register EK binding (anti-Sybil)
  ek_service.register_ek_binding(
    ek_fingerprint_sha256=session["ek_fingerprint_sha256"],
    identity_internal_id=internal_id,
    ek_certificate_pem="(stored in enrollment session)",  # TODO: store full PEM
    tpm_manufacturer_code=manufacturer_code,
    trust_tier=trust_tier,
  )

  # Register handle (if requested)
  display_handle = f"@{internal_id}"
  if session.get("requested_handle"):
    handle_name = session["requested_handle"].lower().lstrip("@")
    # Re-check availability (could have been taken during the 5-minute window)
    if handle_service.check_handle_availability(handle_name) == "available":
      handle_service.register_handle_for_identity(handle_name, internal_id)
      display_handle = f"@{handle_name}"

  # Mark session completed
  enrollment_session_service.mark_enrollment_session_completed(
    request_body.enrollment_session_id
  )

  # Get initial tokens
  initial_tokens = None
  try:
    token_response = await keycloak_service.get_initial_tokens_for_agent(
      client_id=keycloak_credentials["client_id"],
      client_secret=keycloak_credentials["client_secret"],
    )
    initial_tokens = {
      "access_token": token_response["access_token"],
      "refresh_token": token_response.get("refresh_token"),
      "expires_in": token_response.get("expires_in", 3600),
      "token_type": "Bearer",
    }
  except Exception as token_error:
    logger.warning("Could not fetch initial tokens: %s", token_error)

  logger.info(
    "Sovereign enrollment complete: id=%s, handle=%s, tier=%s",
    internal_id, display_handle, trust_tier,
  )

  return _make_success_response(
    {
      "identity": {
        "internal_id": internal_id,
        "handle": display_handle,
        "trust_tier": trust_tier,
        "tpm_manufacturer": manufacturer_code,
        "registered_at": "now",
      },
      "credentials": {
        "client_id": keycloak_credentials["client_id"],
        "client_secret": keycloak_credentials["client_secret"],
        "token_endpoint": config.TOKEN_ENDPOINT,
        "grant_type": "client_credentials",
      },
      "initial_tokens": initial_tokens,
    },
    http_status_code=201,
  )
