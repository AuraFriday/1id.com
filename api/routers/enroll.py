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
  handle_display_form_to_register = None
  if request_body.requested_handle:
    handle_name, handle_display = handle_service.normalize_handle_input(request_body.requested_handle)

    is_valid_handle, handle_error_message = handle_service.validate_handle_name(handle_name)
    if not is_valid_handle:
      return _make_error_response(400, "HANDLE_INVALID", handle_error_message)

    # Check if reserved (static patterns + database reserved_handles table)
    is_reserved, reserved_reason = handle_service.check_handle_is_reserved(handle_name)
    if is_reserved:
      return _make_error_response(403, "HANDLE_RESERVED", reserved_reason)

    availability = handle_service.check_handle_availability(handle_name)
    if availability == "active":
      return _make_error_response(409, "HANDLE_TAKEN", f"Handle '@{handle_name}' is already in use")
    if availability == "retired":
      return _make_error_response(410, "HANDLE_RETIRED", f"Handle '@{handle_name}' has been permanently retired")
    if availability == "expired":
      return _make_error_response(409, "HANDLE_TAKEN", f"Handle '@{handle_name}' is expired but still owned by another identity")

    handle_name_to_register = handle_name
    handle_display_form_to_register = handle_display

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
    handle_service.register_handle_for_identity(
      handle_name_lowercase=handle_name_to_register,
      handle_name_display=handle_display_form_to_register or handle_name_to_register,
      identity_internal_id=internal_id,
    )
    display_handle = f"@{handle_display_form_to_register or handle_name_to_register}"

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
  # Pass ek_public_key_pem as fallback in case the cert can't be parsed by the
  # cryptography library (some Intel firmware TPM certs have non-standard ASN.1).
  ek_fingerprint = ek_service.compute_ek_fingerprint_sha256(
    request_body.ek_certificate_pem,
    ek_public_key_pem=request_body.ek_public_key_pem,
  )
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

  # --- Generate credential activation challenge (TPM2_MakeCredential) ---
  # This is the core crypto: we encrypt a random secret so that ONLY the TPM
  # that owns both the EK and the AK can decrypt it (via ActivateCredential).
  import base64
  from services import tpm_credential_service

  # Step 1: Generate a random 32-byte credential secret.
  # This is what we expect back after the TPM decrypts it.
  credential_secret = enrollment_session_service.generate_credential_challenge_secret()

  # Step 2: Compute the AK's TPM Name from the client-provided TPMT_PUBLIC bytes.
  try:
    ak_tpmt_public_bytes = base64.b64decode(request_body.ak_tpmt_public_b64)
  except Exception:
    return _make_error_response(400, "AK_TPMT_PUBLIC_INVALID", "ak_tpmt_public_b64 is not valid base64")

  ak_tpm_name = tpm_credential_service._compute_ak_name_from_tpm_public_bytes(ak_tpmt_public_bytes)

  # Step 3: Get EK public key PEM for MakeCredential.
  # Try extracting from the certificate first; if that fails (non-standard ASN.1),
  # use the pre-extracted public key that the Go binary sent.
  ek_public_key_pem = None
  try:
    ek_public_key_pem = ek_service.extract_public_key_pem_from_ek_certificate(
      request_body.ek_certificate_pem
    )
  except Exception as extract_error:
    logger.warning("Could not extract public key from EK cert: %s", extract_error)
    if request_body.ek_public_key_pem:
      ek_public_key_pem = request_body.ek_public_key_pem
      logger.info("Using client-provided ek_public_key_pem as fallback")
    else:
      return _make_error_response(
        400, "EK_CERT_INVALID",
        f"Could not extract public key from EK cert and no ek_public_key_pem provided: {extract_error}",
      )

  # Step 4: Run MakeCredential (pure software, no TPM on server).
  try:
    credential_blob, encrypted_secret = tpm_credential_service.make_credential(
      ek_public_key_pem=ek_public_key_pem,
      credential_secret=credential_secret,
      ak_name=ak_tpm_name,
    )
  except Exception as make_cred_error:
    logger.error("MakeCredential failed: %s", make_cred_error)
    return _make_error_response(500, "MAKE_CREDENTIAL_FAILED", f"Server-side MakeCredential error: {make_cred_error}")

  # --- Create enrollment session ---
  session_id = enrollment_session_service.create_enrollment_session(
    ek_fingerprint_sha256=ek_fingerprint,
    ak_public_key_pem=request_body.ak_public_key_pem,
    credential_challenge_bytes=credential_blob,  # stored for reference/debugging
    expected_credential_bytes=credential_secret,  # the secret we expect back
    trust_tier=trust_tier,
    tpm_manufacturer_code=manufacturer_code,
    requested_handle=request_body.requested_handle,
    operator_email=request_body.operator_email,
  )

  # Encode the blobs as base64 for JSON transport to the agent.
  credential_blob_b64 = base64.b64encode(credential_blob).decode("ascii")
  encrypted_secret_b64 = base64.b64encode(encrypted_secret).decode("ascii")

  response_data = {
    "enrollment_session_id": session_id,
    "credential_blob": credential_blob_b64,
    "encrypted_secret": encrypted_secret_b64,
    "trust_tier": trust_tier,
    "tpm_manufacturer": manufacturer_code,
    "expires_in_seconds": config.ENROLLMENT_SESSION_TTL_SECONDS,
  }

  if handle_status_info:
    response_data.update(handle_status_info)

  logger.info(
    "Enrollment session created: session=%s, tier=%s, manufacturer=%s, "
    "credential_blob=%d bytes, encrypted_secret=%d bytes",
    session_id, trust_tier, manufacturer_code,
    len(credential_blob), len(encrypted_secret),
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

  # Register EK binding (anti-Sybil) and persist the AK public key
  # for future challenge-response authentication (TPM2_Sign verification).
  ek_service.register_ek_binding(
    ek_fingerprint_sha256=session["ek_fingerprint_sha256"],
    identity_internal_id=internal_id,
    ek_certificate_pem="(stored in enrollment session)",  # TODO: store full PEM
    tpm_manufacturer_code=manufacturer_code,
    trust_tier=trust_tier,
    ak_public_key_pem=session.get("ak_public_key_pem"),
  )

  # Register handle (if requested)
  display_handle = f"@{internal_id}"
  if session.get("requested_handle"):
    handle_name, handle_display = handle_service.normalize_handle_input(session["requested_handle"])
    # Re-check availability (could have been taken during the 5-minute window)
    if handle_service.check_handle_availability(handle_name) == "available":
      # Also check reserved status (belt and suspenders -- was checked at begin, recheck at activate)
      is_reserved, _ = handle_service.check_handle_is_reserved(handle_name)
      if not is_reserved:
        handle_service.register_handle_for_identity(
          handle_name_lowercase=handle_name,
          handle_name_display=handle_display,
          identity_internal_id=internal_id,
        )
        display_handle = f"@{handle_display}"

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
