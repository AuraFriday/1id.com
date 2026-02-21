"""
1id.com -- Handle Service

Manages vanity handles: validation, pricing, availability, registration,
case-preserving display, reserved patterns, multi-year discount calculation.

Handle lifecycle: active -> expired (unpaid) -> retired (3yr or chargeback).
Retired handles are PERMANENT -- never reusable by anyone.

Handle naming: DNS-compatible labels (RFC 952/1123). Case-insensitive.
Stored lowercase for lookups; display form preserves owner's preferred casing.
"""

import math
import re

# ---------------------------------------------------------------------------
# Handle naming rules (DNS-compatible labels, RFC 952/1123)
# ---------------------------------------------------------------------------

_HANDLE_MIN_LENGTH = 1
_HANDLE_MAX_LENGTH = 63  # DNS label max

# Only lowercase a-z, digits 0-9, and hyphens. Must start and end with
# alphanumeric. No consecutive hyphens (breaks punycode).
# No dots (DNS separators). No underscores (not valid in DNS labels).
_HANDLE_PATTERN_FOR_DNS_COMPATIBLE_LABELS = re.compile(
  r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
)

_CONSECUTIVE_HYPHENS_DETECTOR = re.compile(r"--")

# ---------------------------------------------------------------------------
# Reserved patterns -- handles that cannot be registered by the public
# ---------------------------------------------------------------------------

# Handles starting with '1id' (case-insensitive) are reserved to prevent
# confusion with internal IDs (1id-K7X9M2Q4) and protect our brand.
_RESERVED_PREFIX_PATTERNS = ["1id"]

# Exact-match reserved names (stored lowercase).
_RESERVED_EXACT_NAMES = frozenset({
  # Service names
  "admin", "administrator", "root", "system", "support", "help",
  # Sentinel values that could cause bugs if used as identifiers
  "null", "undefined", "none", "void", "deleted", "revoked", "suspended",
  "true", "false", "yes", "no",
  # DNS/infrastructure names
  "www", "api", "mail", "ftp", "ns", "ns1", "ns2", "mx", "smtp", "imap",
  "pop", "pop3", "dns", "vpn", "ssh", "sftp",
  # RFC 2142 required addresses (mailboxes that must exist on mail servers)
  "postmaster", "abuse", "webmaster", "hostmaster", "noc", "security",
  "info", "marketing", "sales",
  # Common impersonation targets
  "1id", "oneid", "1id-com", "oneidentity",
})


# ---------------------------------------------------------------------------
# Pricing tiers and annual fees (USD cents)
# ---------------------------------------------------------------------------

_PRICING_TIERS = {
  "permanent_random": {"annual_fee_cents_usd": 0,       "label": "Free forever"},
  "1char":            {"annual_fee_cents_usd": 500000,   "label": "$5,000/year"},
  "2char":            {"annual_fee_cents_usd": 100000,   "label": "$1,000/year"},
  "3char":            {"annual_fee_cents_usd": 50000,    "label": "$500/year"},
  "4char":            {"annual_fee_cents_usd": 20000,    "label": "$200/year"},
  "5char":            {"annual_fee_cents_usd": 5000,     "label": "$50/year"},
  "6plus":            {"annual_fee_cents_usd": 1000,     "label": "$10/year"},
  "vip_lifetime":     {"annual_fee_cents_usd": 0,        "label": "Lifetime (VIP)"},
}


# ---------------------------------------------------------------------------
# Multi-year discount constants
#
# 4% compound discount per year (1pp better than ~3% inflation).
# Hard floor at 50% of annual fee per year -- every year must cost real money.
# Floor kicks in at year K=17 (ceil(ln(0.5) / ln(0.96))).
# ---------------------------------------------------------------------------

_DISCOUNT_RATE_PER_YEAR = 0.96  # each year costs 96% of the previous year
_DISCOUNT_FLOOR_FRACTION = 0.50  # no year costs less than 50% of annual fee
_DISCOUNT_FLOOR_YEAR_K = math.ceil(
  math.log(_DISCOUNT_FLOOR_FRACTION) / math.log(_DISCOUNT_RATE_PER_YEAR)
)  # = 17


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_handle_input(raw_input):
  """
  Normalize a user-supplied handle string for storage and lookup.

  - Strips leading '@' if present
  - Lowercases for comparison/storage
  - Returns (lowercase_form, display_form) where display_form preserves
    the casing the user entered (minus any leading '@').

  Returns: (handle_name_lowercase, handle_name_display)
  """
  if not raw_input:
    return ("", "")
  # Strip leading '@' (users may include it)
  display_form = raw_input.lstrip("@")
  lowercase_form = display_form.lower()
  return (lowercase_form, display_form)


def validate_handle_name(handle_name_lowercase):
  """
  Validate a handle name (must already be lowercased).
  Returns (is_valid, error_message).

  Rules (DNS-compatible labels, RFC 952/1123):
  - 1-63 characters
  - Lowercase letters a-z, digits 0-9, hyphens only
  - Must start and end with a letter or digit (not hyphen)
  - No consecutive hyphens (breaks punycode)
  - No dots, no underscores
  """
  if not handle_name_lowercase:
    return False, "Handle name cannot be empty"

  if len(handle_name_lowercase) < _HANDLE_MIN_LENGTH:
    return False, f"Handle must be at least {_HANDLE_MIN_LENGTH} character"

  if len(handle_name_lowercase) > _HANDLE_MAX_LENGTH:
    return False, f"Handle must be at most {_HANDLE_MAX_LENGTH} characters"

  # Must be lowercase (caller should have normalized, but defense in depth)
  if handle_name_lowercase != handle_name_lowercase.lower():
    return False, "Handle must be lowercase (use normalize_handle_input first)"

  # Must match DNS label pattern
  if not _HANDLE_PATTERN_FOR_DNS_COMPATIBLE_LABELS.match(handle_name_lowercase):
    return False, (
      "Handle must contain only lowercase letters (a-z), digits (0-9), "
      "and hyphens (-). Must start and end with a letter or digit."
    )

  # No consecutive hyphens (also checked by the regex for most cases,
  # but explicit check is clearer and catches edge cases)
  if _CONSECUTIVE_HYPHENS_DETECTOR.search(handle_name_lowercase):
    return False, "Handle must not contain consecutive hyphens (--)"

  return True, None


def check_handle_is_reserved(handle_name_lowercase):
  """
  Check if a handle is reserved (cannot be registered by the public).

  Checks:
  1. Static prefix patterns (e.g., anything starting with '1id')
  2. Static exact-match reserved names
  3. Database reserved_handles table (operator's personal list, legacy I-Names, etc.)

  Returns: (is_reserved, reason) or (False, None)
  """
  # 1. Prefix patterns
  for prefix in _RESERVED_PREFIX_PATTERNS:
    if handle_name_lowercase.startswith(prefix.lower()):
      return True, f"Handles starting with '{prefix}' are reserved"

  # 2. Exact-match reserved names
  if handle_name_lowercase in _RESERVED_EXACT_NAMES:
    return True, f"'{handle_name_lowercase}' is a reserved name"

  # 3. Database reserved_handles table
  import database
  row = database.execute_query_returning_one_row(
    "SELECT handle_name_lowercase, reason FROM reserved_handles WHERE handle_name_lowercase = %s",
    (handle_name_lowercase,)
  )
  if row is not None:
    reason = row.get("reason") or "This handle is reserved"
    return True, reason

  return False, None


def classify_handle_pricing_tier(handle_name_lowercase):
  """
  Determine pricing tier based on handle length.
  All vanity handles are paid. Only @1id-xxxx random handles are free.
  """
  length = len(handle_name_lowercase)
  if length >= 6:
    return "6plus"
  if length == 5:
    return "5char"
  if length == 4:
    return "4char"
  if length == 3:
    return "3char"
  if length == 2:
    return "2char"
  if length == 1:
    return "1char"
  # Should never reach here due to validation, but defense in depth
  return "6plus"


def get_annual_fee_cents_usd(pricing_tier):
  """Get the annual fee in USD cents for a pricing tier."""
  tier_info = _PRICING_TIERS.get(pricing_tier)
  if tier_info is None:
    raise ValueError(f"Unknown pricing tier: {pricing_tier}")
  return tier_info["annual_fee_cents_usd"]


def get_pricing_tier_label(pricing_tier):
  """Get the human-readable label for a pricing tier."""
  tier_info = _PRICING_TIERS.get(pricing_tier)
  if tier_info is None:
    return "Unknown"
  return tier_info["label"]


def calculate_multi_year_total_cents_usd(annual_fee_cents_usd, years):
  """
  Calculate total cost for a multi-year registration.

  Uses 4% compound discount per year, floored at 50% of annual fee.
  Every year costs real money; no year is ever free.

  Formula:
    K = 17 (year where 50% floor kicks in)
    If years <= K: total = annual_fee * (1 - 0.96^years) / 0.04
    If years > K:  total = annual_fee * (1 - 0.96^K) / 0.04
                         + annual_fee * 0.50 * (years - K)

  Returns: total cost in USD cents (integer, rounded up to nearest cent)
  """
  if years < 1:
    raise ValueError("Years must be at least 1")
  if not isinstance(years, int):
    raise TypeError("Years must be an integer")
  if annual_fee_cents_usd <= 0:
    # Free handles (permanent_random, vip_lifetime) cost nothing regardless
    return 0

  k = min(years, _DISCOUNT_FLOOR_YEAR_K)

  # Compounding portion (years 1 through K)
  compounding_portion = annual_fee_cents_usd * (
    1.0 - _DISCOUNT_RATE_PER_YEAR ** k
  ) / (1.0 - _DISCOUNT_RATE_PER_YEAR)

  # Floor portion (years K+1 through N, each at 50% of annual fee)
  floor_years = max(0, years - _DISCOUNT_FLOOR_YEAR_K)
  floor_portion = annual_fee_cents_usd * _DISCOUNT_FLOOR_FRACTION * floor_years

  total_float = compounding_portion + floor_portion

  # Round up to nearest cent (never round down -- we don't give away fractions)
  return math.ceil(total_float)


def calculate_multi_year_discount_summary(annual_fee_cents_usd, years):
  """
  Calculate discount summary for display to user.

  Returns dict with:
    total_cents_usd: total cost in cents
    full_price_cents_usd: what it would cost without discount
    savings_cents_usd: how much the buyer saves
    effective_per_year_cents_usd: average per-year cost
  """
  total_cents = calculate_multi_year_total_cents_usd(annual_fee_cents_usd, years)
  full_price_cents = annual_fee_cents_usd * years
  savings_cents = full_price_cents - total_cents

  return {
    "total_cents_usd": total_cents,
    "full_price_cents_usd": full_price_cents,
    "savings_cents_usd": savings_cents,
    "effective_per_year_cents_usd": math.ceil(total_cents / years) if years > 0 else 0,
    "years": years,
    "annual_fee_cents_usd": annual_fee_cents_usd,
  }


def check_handle_availability(handle_name_lowercase):
  """
  Check if a handle is available for registration.

  Returns one of:
    'available' - can be registered
    'active'    - currently owned and in use
    'expired'   - owned but unpaid, owner can still renew (0-3 years)
    'payment_dispute' - owned but payment dispute in progress
    'retired'   - permanently destroyed, can never be used again
  """
  import database
  row = database.execute_query_returning_one_row(
    "SELECT status FROM handles WHERE handle_name = %s",
    (handle_name_lowercase,)
  )
  if row is None:
    return "available"
  return row["status"]


def check_identity_has_active_vanity_handle(identity_internal_id):
  """
  Check if an identity already has an active vanity handle.
  Rule: one vanity handle per identity, period.

  Returns: handle_name (str) if they have one, or None
  """
  import database
  row = database.execute_query_returning_one_row(
    """
    SELECT handle_name FROM handles
    WHERE identity_internal_id = %s AND status = 'active'
    LIMIT 1
    """,
    (identity_internal_id,)
  )
  if row:
    return row["handle_name"]
  return None


def register_handle_for_identity(
  handle_name_lowercase,
  handle_name_display,
  identity_internal_id,
  pricing_tier=None,
  expires_at=None,
  subscription_provider=None,
  subscription_provider_id=None,
  auto_renew=True,
  paid_through_date=None,
):
  """
  Register a handle for an identity.

  Caller MUST validate, check availability, check reservations,
  and verify the identity doesn't already have an active vanity handle.

  Args:
    handle_name_lowercase: The handle in lowercase (PK).
    handle_name_display: The case-preserved form the owner entered.
    identity_internal_id: The identity this handle belongs to.
    pricing_tier: Override pricing tier (e.g., 'vip_lifetime'). Auto-detected if None.
    expires_at: When the handle expires (None for lifetime/free handles).
    subscription_provider: 'paypal', 'stripe', etc. (None for free/lifetime).
    subscription_provider_id: External subscription ID.
    auto_renew: Whether the subscription auto-renews (default True).
    paid_through_date: Date through which the handle is paid.
  """
  if pricing_tier is None:
    pricing_tier = classify_handle_pricing_tier(handle_name_lowercase)

  import database
  database.execute_insert_or_update(
    """
    INSERT INTO handles
      (handle_name, handle_name_display, identity_internal_id, status,
       pricing_tier, expires_at, paid_through_date,
       subscription_provider, subscription_provider_id, auto_renew)
    VALUES (%s, %s, %s, 'active', %s, %s, %s, %s, %s, %s)
    """,
    (
      handle_name_lowercase,
      handle_name_display,
      identity_internal_id,
      pricing_tier,
      expires_at,
      paid_through_date,
      subscription_provider,
      subscription_provider_id,
      1 if auto_renew else 0,
    )
  )


def get_active_handle_for_identity(identity_internal_id):
  """
  Get the active vanity handle for an identity, or None.
  Returns the display form (case-preserved).
  """
  import database
  row = database.execute_query_returning_one_row(
    """
    SELECT handle_name_display FROM handles
    WHERE identity_internal_id = %s AND status = 'active'
    LIMIT 1
    """,
    (identity_internal_id,)
  )
  if row and row.get("handle_name_display"):
    return f"@{row['handle_name_display']}"
  # Fallback: if display form is somehow missing, use lowercase
  if row:
    fallback_row = database.execute_query_returning_one_row(
      """
      SELECT handle_name FROM handles
      WHERE identity_internal_id = %s AND status = 'active'
      LIMIT 1
      """,
      (identity_internal_id,)
    )
    if fallback_row:
      return f"@{fallback_row['handle_name']}"
  return None


def get_display_handle_for_identity(identity_internal_id):
  """
  Get the display handle for an identity.
  If active vanity handle exists: @DisplayForm (case-preserved)
  Otherwise: @1id-XXXXXXXX (the internal ID as fallback)
  """
  active_handle = get_active_handle_for_identity(identity_internal_id)
  if active_handle:
    return active_handle
  return f"@{identity_internal_id}"
