"""
1id.com -- Handle Service

Manages vanity handles: registration, availability check, dormancy, retirement.
Handle lifecycle: active -> dormant (not renewed) -> retired (cancelled/grace expired).
Retired handles are PERMANENT -- never reusable by anyone.
"""

import re
import database


# Handle naming rules
_HANDLE_MIN_LENGTH = 1
_HANDLE_MAX_LENGTH = 64
_HANDLE_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")

# Pricing tiers based on length
_PRICING_TIERS_BY_LENGTH = {
  1: "1char",
  2: "2char",
  3: "3char",
  4: "4char",
  5: "5char",
}


def classify_handle_pricing_tier(handle_name):
  """Determine pricing tier based on handle length."""
  length = len(handle_name)
  if length in _PRICING_TIERS_BY_LENGTH:
    return _PRICING_TIERS_BY_LENGTH[length]
  return "free"  # 6+ characters are free


def validate_handle_name(handle_name):
  """
  Validate a handle name. Returns (is_valid, error_message).

  Rules:
  - 1-64 characters
  - Lowercase alphanumeric, dots, hyphens, underscores
  - Must start and end with alphanumeric
  - No consecutive dots/hyphens/underscores
  """
  if not handle_name:
    return False, "Handle name cannot be empty"

  if len(handle_name) < _HANDLE_MIN_LENGTH:
    return False, f"Handle must be at least {_HANDLE_MIN_LENGTH} character"

  if len(handle_name) > _HANDLE_MAX_LENGTH:
    return False, f"Handle must be at most {_HANDLE_MAX_LENGTH} characters"

  # Must be lowercase
  if handle_name != handle_name.lower():
    return False, "Handle must be lowercase"

  # Must match pattern
  if not _HANDLE_PATTERN.match(handle_name):
    return False, "Handle must contain only lowercase letters, digits, dots, hyphens, and underscores, and must start and end with a letter or digit"

  # No consecutive special characters
  if ".." in handle_name or "--" in handle_name or "__" in handle_name:
    return False, "Handle must not contain consecutive dots, hyphens, or underscores"

  return True, None


def check_handle_availability(handle_name):
  """
  Check if a handle is available.
  Returns: 'available', 'taken', 'dormant', or 'retired'.
  """
  row = database.execute_query_returning_one_row(
    "SELECT status FROM handles WHERE handle_name = %s",
    (handle_name.lower(),)
  )
  if row is None:
    return "available"
  return row["status"]


def register_handle_for_identity(handle_name, identity_internal_id):
  """
  Register a handle for an identity. Caller must validate and check
  availability first.
  """
  pricing_tier = classify_handle_pricing_tier(handle_name)
  database.execute_insert_or_update(
    """
    INSERT INTO handles (handle_name, identity_internal_id, status, pricing_tier)
    VALUES (%s, %s, 'active', %s)
    """,
    (handle_name.lower(), identity_internal_id, pricing_tier)
  )


def get_active_handle_for_identity(identity_internal_id):
  """
  Get the active vanity handle for an identity, or None.
  An identity can have multiple handles but only one active at a time
  (for the JWT claim).
  """
  row = database.execute_query_returning_one_row(
    """
    SELECT handle_name FROM handles
    WHERE identity_internal_id = %s AND status = 'active'
    ORDER BY registered_at ASC
    LIMIT 1
    """,
    (identity_internal_id,)
  )
  if row:
    return f"@{row['handle_name']}"
  return None


def get_display_handle_for_identity(identity_internal_id):
  """
  Get the display handle for an identity.
  If active vanity handle exists: @vanity_name
  Otherwise: @1id_XXXXXXXX (the internal ID as fallback)
  """
  active_handle = get_active_handle_for_identity(identity_internal_id)
  if active_handle:
    return active_handle
  return f"@{identity_internal_id}"
