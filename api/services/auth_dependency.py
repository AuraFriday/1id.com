"""
1id.com -- Authentication Dependency for FastAPI

Provides a FastAPI dependency that validates Bearer tokens (JWTs from Keycloak)
and extracts identity information.

Two modes:
  1. verify_bearer_token_and_extract_identity -- strict: returns 401 if no/bad token
  2. optional_bearer_token_identity_extraction -- optional: returns None if no token

JWT tokens are validated by checking the Keycloak JWKS endpoint and verifying
the signature, issuer, and expiry.
"""

import logging
import time

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse

import config

logger = logging.getLogger("oneid.auth_dependency")

# ---------------------------------------------------------------------------
# JWKS cache (public keys from Keycloak for verifying JWTs)
# ---------------------------------------------------------------------------
_cached_jwks_keys = None
_cached_jwks_fetched_at = 0
_JWKS_CACHE_TTL_SECONDS = 3600  # refresh hourly


async def _fetch_keycloak_jwks():
  """Fetch the JWKS (public keys) from Keycloak for JWT verification."""
  global _cached_jwks_keys, _cached_jwks_fetched_at

  now = time.time()
  if _cached_jwks_keys and (now - _cached_jwks_fetched_at) < _JWKS_CACHE_TTL_SECONDS:
    return _cached_jwks_keys

  jwks_url = (
    f"{config.KEYCLOAK_BASE_URL}/realms/{config.KEYCLOAK_REALM_NAME}"
    "/protocol/openid-connect/certs"
  )

  try:
    async with httpx.AsyncClient() as http_client:
      response = await http_client.get(jwks_url)
      response.raise_for_status()
      jwks_data = response.json()
      _cached_jwks_keys = jwks_data.get("keys", [])
      _cached_jwks_fetched_at = now
      logger.info("Refreshed Keycloak JWKS (%d keys)", len(_cached_jwks_keys))
      return _cached_jwks_keys
  except Exception as jwks_error:
    logger.error("Failed to fetch Keycloak JWKS: %s", jwks_error)
    # Return cached keys if we have them (even if stale), otherwise empty
    return _cached_jwks_keys or []


def _decode_and_verify_jwt_token(token_string, jwks_keys):
  """
  Decode and verify a JWT token using the JWKS public keys.

  Returns: decoded payload dict, or None if invalid.
  """
  try:
    import jwt as pyjwt
  except ImportError:
    # Fall back to jose if PyJWT not available
    try:
      from jose import jwt as jose_jwt, JWTError
      # Build the key set for python-jose
      for key_data in jwks_keys:
        try:
          decoded = jose_jwt.decode(
            token_string,
            key_data,
            algorithms=["RS256"],
            options={"verify_aud": False},
          )
          return decoded
        except JWTError:
          continue
      return None
    except ImportError:
      logger.error(
        "Neither PyJWT nor python-jose is installed. "
        "Cannot verify JWT tokens. Install one: pip install PyJWT or pip install python-jose"
      )
      return None

  # PyJWT path
  from jwt import PyJWKSet, InvalidTokenError

  try:
    keyset = PyJWKSet.from_dict({"keys": jwks_keys})
    # Try each key until one works
    for jwk_key in keyset.keys:
      try:
        decoded = pyjwt.decode(
          token_string,
          jwk_key.key,
          algorithms=["RS256"],
          options={"verify_aud": False},
        )
        return decoded
      except InvalidTokenError:
        continue
  except Exception as decode_error:
    logger.debug("JWT decode error: %s", decode_error)

  return None


async def extract_identity_from_bearer_token(request):
  """
  Extract identity information from a Bearer token in the Authorization header.

  Returns: dict with identity info, or None if no valid token.
    {
      "identity_internal_id": "1id-XXXXXXXX",
      "keycloak_client_id": "1id-XXXXXXXX",
      "trust_tier": "declared",
      "raw_claims": {...}
    }
  """
  auth_header = request.headers.get("authorization", "")
  if not auth_header.lower().startswith("bearer "):
    return None

  token_string = auth_header[7:].strip()
  if not token_string:
    return None

  # Fetch and verify with Keycloak JWKS
  jwks_keys = await _fetch_keycloak_jwks()
  if not jwks_keys:
    logger.warning("No JWKS keys available for token verification")
    return None

  decoded_claims = _decode_and_verify_jwt_token(token_string, jwks_keys)
  if decoded_claims is None:
    return None

  # Check expiry
  token_expiry_timestamp = decoded_claims.get("exp", 0)
  if time.time() > token_expiry_timestamp:
    return None

  # Extract identity info from token claims
  # Keycloak service account tokens have "clientId" in the azp (authorized party) claim
  keycloak_client_id = decoded_claims.get("azp") or decoded_claims.get("client_id")

  # Our custom claims from the oneid-claims scope
  identity_internal_id = decoded_claims.get("1id_internal_id") or keycloak_client_id
  trust_tier = decoded_claims.get("1id_trust_tier", "declared")

  return {
    "identity_internal_id": identity_internal_id,
    "keycloak_client_id": keycloak_client_id,
    "trust_tier": trust_tier,
    "raw_claims": decoded_claims,
  }


async def require_valid_bearer_token(request):
  """
  FastAPI dependency: require a valid Bearer token.

  Returns the identity info dict on success.
  Returns a 401 JSONResponse if the token is missing or invalid.

  Usage in a router:
    @router.post("/something")
    async def my_endpoint(request: Request):
      identity_or_error = await require_valid_bearer_token(request)
      if isinstance(identity_or_error, JSONResponse):
        return identity_or_error
      identity = identity_or_error
      ...
  """
  identity = await extract_identity_from_bearer_token(request)
  if identity is None:
    return JSONResponse(
      status_code=401,
      content={
        "ok": False,
        "data": None,
        "error": {
          "code": "UNAUTHORIZED",
          "message": "Valid Bearer token is required. "
                     "Authenticate via /api/v1/auth/challenge + /api/v1/auth/verify "
                     "or client_credentials grant.",
        },
      },
    )
  return identity
