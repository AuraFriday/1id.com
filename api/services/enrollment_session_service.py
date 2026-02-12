"""
1id.com -- Enrollment Session Service

Manages temporary sessions for the two-phase TPM enrollment flow:
  1. /enroll/begin  -> creates session with credential challenge
  2. /enroll/activate -> verifies decrypted credential, completes enrollment

Sessions expire after 5 minutes (configurable).
"""

import secrets
import base64
import database
import config
from datetime import datetime, timezone, timedelta


def generate_session_id():
  """Generate a unique enrollment session ID: es_<random hex>."""
  return f"es_{secrets.token_hex(12)}"


def generate_credential_challenge():
  """
  Generate a random credential challenge for TPM2_MakeCredential.

  Returns: (challenge_bytes, challenge_base64)
    - challenge_bytes: raw bytes to use in MakeCredential
    - challenge_base64: base64-encoded version for JSON transport
  """
  challenge_bytes = secrets.token_bytes(32)
  challenge_base64 = base64.b64encode(challenge_bytes).decode("ascii")
  return challenge_bytes, challenge_base64


def create_enrollment_session(
  ek_fingerprint_sha256,
  ak_public_key_pem,
  credential_challenge_bytes,
  expected_credential_bytes,
  trust_tier,
  tpm_manufacturer_code,
  requested_handle=None,
  operator_email=None,
):
  """
  Create a new enrollment session in the database.
  Returns the session_id.
  """
  session_id = generate_session_id()
  expires_at = datetime.now(timezone.utc) + timedelta(
    seconds=config.ENROLLMENT_SESSION_TTL_SECONDS
  )

  database.execute_insert_or_update(
    """
    INSERT INTO enrollment_sessions
      (session_id, ek_fingerprint_sha256, ak_public_key_pem,
       credential_challenge, expected_credential, trust_tier,
       tpm_manufacturer_code, requested_handle, operator_email,
       expires_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """,
    (
      session_id,
      ek_fingerprint_sha256,
      ak_public_key_pem,
      credential_challenge_bytes,
      expected_credential_bytes,
      trust_tier,
      tpm_manufacturer_code,
      requested_handle,
      operator_email,
      expires_at,
    )
  )

  return session_id


def get_enrollment_session(session_id):
  """
  Look up an enrollment session. Returns dict or None.
  Only returns non-expired, non-completed sessions.
  """
  row = database.execute_query_returning_one_row(
    """
    SELECT * FROM enrollment_sessions
    WHERE session_id = %s AND completed = 0 AND expires_at > NOW()
    """,
    (session_id,)
  )
  return row


def mark_enrollment_session_completed(session_id):
  """Mark a session as completed (credential was successfully activated)."""
  database.execute_insert_or_update(
    "UPDATE enrollment_sessions SET completed = 1 WHERE session_id = %s",
    (session_id,)
  )


def cleanup_expired_sessions():
  """Delete expired, non-completed sessions. Called periodically."""
  database.execute_insert_or_update(
    "DELETE FROM enrollment_sessions WHERE expires_at < NOW() AND completed = 0"
  )
