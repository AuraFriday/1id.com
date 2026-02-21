"""
1id.com -- Identity Service

Generates unique internal IDs, creates identity records in MySQL,
and manages identity lookups.
"""

import secrets
import string
import database
import config

# Base36 charset for internal ID generation (digits + lowercase letters)
_BASE36_ALPHABET = string.digits + string.ascii_uppercase


def generate_unique_internal_id():
  """
  Generate a unique 1id internal ID in the format: 1id-XXXXXXXX
  where X is base36 alphanumeric. Checks DB for collisions.

  The ID is 8 characters of base36 = 36^8 = ~2.8 trillion combinations.
  With birthday paradox, collision at ~1.7 million identities is ~50%.
  We retry on collision, so this is safe for millions of identities.
  """
  max_collision_retries = 10
  for _attempt in range(max_collision_retries):
    random_part = "".join(
      secrets.choice(_BASE36_ALPHABET)
      for _ in range(config.INTERNAL_ID_LENGTH)
    )
    candidate_id = f"{config.INTERNAL_ID_PREFIX}{random_part}"

    # Check for collision
    existing = database.execute_query_returning_one_row(
      "SELECT internal_id FROM identities WHERE internal_id = %s",
      (candidate_id,)
    )
    if existing is None:
      return candidate_id

  raise RuntimeError(
    "Failed to generate unique internal ID after "
    f"{max_collision_retries} attempts -- this should never happen"
  )


def create_declared_tier_identity(
  internal_id,
  keycloak_client_id,
  operator_email=None,
):
  """Insert a new declared-tier identity into the database."""
  database.execute_insert_or_update(
    """
    INSERT INTO identities
      (internal_id, trust_tier, operator_email, keycloak_client_id)
    VALUES (%s, %s, %s, %s)
    """,
    (internal_id, "declared", operator_email, keycloak_client_id)
  )


def create_sovereign_tier_identity(
  internal_id,
  trust_tier,
  keycloak_client_id,
  operator_email=None,
):
  """Insert a new sovereign/legacy/virtual identity into the database."""
  database.execute_insert_or_update(
    """
    INSERT INTO identities
      (internal_id, trust_tier, operator_email, keycloak_client_id)
    VALUES (%s, %s, %s, %s)
    """,
    (internal_id, trust_tier, operator_email, keycloak_client_id)
  )


def get_identity_by_internal_id(internal_id):
  """Look up an identity by its internal ID. Returns dict or None."""
  return database.execute_query_returning_one_row(
    "SELECT * FROM identities WHERE internal_id = %s",
    (internal_id,)
  )


def get_identity_by_keycloak_client_id(keycloak_client_id):
  """Look up identity by Keycloak client ID (used during token issuance)."""
  return database.execute_query_returning_one_row(
    "SELECT * FROM identities WHERE keycloak_client_id = %s",
    (keycloak_client_id,)
  )


def update_last_authentication_timestamp(internal_id):
  """Update last_authentication_at to NOW() for activity tracking."""
  database.execute_insert_or_update(
    "UPDATE identities SET last_authentication_at = NOW() WHERE internal_id = %s",
    (internal_id,)
  )
