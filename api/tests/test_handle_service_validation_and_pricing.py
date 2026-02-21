"""
Unit tests for handle_service.py -- validation, pricing, and discount logic.

Tests cover:
  1. Handle name validation (DNS-compatible rules)
  2. Case normalization and display preservation
  3. Reserved pattern detection (static patterns only; DB-backed tests need integration)
  4. Pricing tier classification
  5. Annual fee lookups
  6. Multi-year discount calculation (including edge cases and abuse)
  7. Security: injection attempts, boundary values, type confusion

These tests are PURE LOGIC tests -- they do NOT touch the database.
Database-dependent tests (availability, registration, reserved_handles table)
are in a separate integration test file.

Run with: python -m pytest tests/test_handle_service_validation_and_pricing.py -v
"""

import math
import os
import sys

# Add the api directory to the path so we can import services
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services import handle_service


# ===================================================================
# 1. normalize_handle_input
# ===================================================================

class TestNormalizeHandleInput:
  """Tests for normalize_handle_input()."""

  def test_simple_lowercase_input(self):
    lowercase, display = handle_service.normalize_handle_input("clawdia")
    assert lowercase == "clawdia"
    assert display == "clawdia"

  def test_mixed_case_preserves_display(self):
    lowercase, display = handle_service.normalize_handle_input("ChrisDrake")
    assert lowercase == "chrisdrake"
    assert display == "ChrisDrake"

  def test_all_uppercase_preserves_display(self):
    lowercase, display = handle_service.normalize_handle_input("TESLA")
    assert lowercase == "tesla"
    assert display == "TESLA"

  def test_strips_leading_at_sign(self):
    lowercase, display = handle_service.normalize_handle_input("@clawdia")
    assert lowercase == "clawdia"
    assert display == "clawdia"

  def test_strips_multiple_leading_at_signs(self):
    lowercase, display = handle_service.normalize_handle_input("@@clawdia")
    assert lowercase == "clawdia"
    assert display == "clawdia"

  def test_at_sign_with_mixed_case(self):
    lowercase, display = handle_service.normalize_handle_input("@ChrisDrake")
    assert lowercase == "chrisdrake"
    assert display == "ChrisDrake"

  def test_empty_string(self):
    lowercase, display = handle_service.normalize_handle_input("")
    assert lowercase == ""
    assert display == ""

  def test_none_input(self):
    lowercase, display = handle_service.normalize_handle_input(None)
    assert lowercase == ""
    assert display == ""

  def test_only_at_sign(self):
    lowercase, display = handle_service.normalize_handle_input("@")
    assert lowercase == ""
    assert display == ""

  def test_digits_and_hyphens(self):
    lowercase, display = handle_service.normalize_handle_input("bot-9000")
    assert lowercase == "bot-9000"
    assert display == "bot-9000"


# ===================================================================
# 2. validate_handle_name (DNS-compatible rules)
# ===================================================================

class TestValidateHandleName:
  """Tests for validate_handle_name() -- DNS-compatible label rules."""

  # --- Valid handles ---

  def test_simple_lowercase(self):
    is_valid, error = handle_service.validate_handle_name("clawdia")
    assert is_valid is True
    assert error is None

  def test_single_character(self):
    is_valid, error = handle_service.validate_handle_name("a")
    assert is_valid is True

  def test_single_digit(self):
    is_valid, error = handle_service.validate_handle_name("7")
    assert is_valid is True

  def test_max_length_63_chars(self):
    name = "a" * 63
    is_valid, error = handle_service.validate_handle_name(name)
    assert is_valid is True

  def test_with_hyphens(self):
    is_valid, error = handle_service.validate_handle_name("my-cool-bot")
    assert is_valid is True

  def test_digits_and_letters_mixed(self):
    is_valid, error = handle_service.validate_handle_name("bot9000x")
    assert is_valid is True

  def test_starts_with_digit(self):
    is_valid, error = handle_service.validate_handle_name("9lives")
    assert is_valid is True

  def test_ends_with_digit(self):
    is_valid, error = handle_service.validate_handle_name("agent007")
    assert is_valid is True

  def test_hyphen_in_middle(self):
    is_valid, error = handle_service.validate_handle_name("a-b")
    assert is_valid is True

  def test_two_characters(self):
    is_valid, error = handle_service.validate_handle_name("ai")
    assert is_valid is True

  # --- Invalid handles: empty/length ---

  def test_empty_string(self):
    is_valid, error = handle_service.validate_handle_name("")
    assert is_valid is False
    assert "empty" in error.lower()

  def test_too_long_64_chars(self):
    name = "a" * 64
    is_valid, error = handle_service.validate_handle_name(name)
    assert is_valid is False
    assert "63" in error

  def test_way_too_long(self):
    name = "a" * 1000
    is_valid, error = handle_service.validate_handle_name(name)
    assert is_valid is False

  # --- Invalid handles: forbidden characters ---

  def test_uppercase_rejected(self):
    is_valid, error = handle_service.validate_handle_name("ChrisDrake")
    assert is_valid is False
    assert "lowercase" in error.lower()

  def test_underscore_rejected(self):
    """Underscores are NOT valid in DNS labels (RFC 952/1123)."""
    is_valid, error = handle_service.validate_handle_name("my_bot")
    assert is_valid is False

  def test_dot_rejected(self):
    """Dots are DNS separators, not allowed in handles."""
    is_valid, error = handle_service.validate_handle_name("my.bot")
    assert is_valid is False

  def test_space_rejected(self):
    is_valid, error = handle_service.validate_handle_name("my bot")
    assert is_valid is False

  def test_at_sign_rejected(self):
    is_valid, error = handle_service.validate_handle_name("@clawdia")
    assert is_valid is False

  def test_slash_rejected(self):
    is_valid, error = handle_service.validate_handle_name("bot/admin")
    assert is_valid is False

  def test_unicode_rejected(self):
    is_valid, error = handle_service.validate_handle_name("böt")
    assert is_valid is False

  def test_emoji_rejected(self):
    is_valid, error = handle_service.validate_handle_name("bot🤖")
    assert is_valid is False

  def test_null_byte_rejected(self):
    """Security: null bytes must not bypass validation."""
    is_valid, error = handle_service.validate_handle_name("bot\x00admin")
    assert is_valid is False

  def test_newline_rejected(self):
    """Security: newlines must not bypass validation."""
    is_valid, error = handle_service.validate_handle_name("bot\nadmin")
    assert is_valid is False

  def test_tab_rejected(self):
    is_valid, error = handle_service.validate_handle_name("bot\tadmin")
    assert is_valid is False

  # --- Invalid handles: hyphen placement ---

  def test_starts_with_hyphen(self):
    is_valid, error = handle_service.validate_handle_name("-bot")
    assert is_valid is False

  def test_ends_with_hyphen(self):
    is_valid, error = handle_service.validate_handle_name("bot-")
    assert is_valid is False

  def test_consecutive_hyphens(self):
    """Consecutive hyphens break punycode encoding."""
    is_valid, error = handle_service.validate_handle_name("my--bot")
    assert is_valid is False
    assert "--" in error

  def test_triple_hyphens(self):
    is_valid, error = handle_service.validate_handle_name("my---bot")
    assert is_valid is False

  # --- Security: SQL injection attempts ---

  def test_sql_injection_single_quote(self):
    is_valid, error = handle_service.validate_handle_name("bot'; DROP TABLE handles;--")
    assert is_valid is False

  def test_sql_injection_union(self):
    is_valid, error = handle_service.validate_handle_name("bot UNION SELECT * FROM identities")
    assert is_valid is False

  def test_sql_injection_comment(self):
    is_valid, error = handle_service.validate_handle_name("bot/**/admin")
    assert is_valid is False

  # --- Security: path traversal attempts ---

  def test_path_traversal(self):
    is_valid, error = handle_service.validate_handle_name("../../../etc/passwd")
    assert is_valid is False

  def test_backslash_path(self):
    is_valid, error = handle_service.validate_handle_name("bot\\admin")
    assert is_valid is False

  # --- Security: XSS attempts ---

  def test_xss_script_tag(self):
    is_valid, error = handle_service.validate_handle_name("<script>alert(1)</script>")
    assert is_valid is False

  def test_xss_event_handler(self):
    is_valid, error = handle_service.validate_handle_name('bot"onload="alert(1)')
    assert is_valid is False


# ===================================================================
# 3. Reserved pattern detection (static patterns only)
# ===================================================================

class TestCheckHandleIsReservedStaticPatterns:
  """
  Tests for check_handle_is_reserved() -- static prefix and exact-match only.

  NOTE: These tests mock the database call to avoid needing a live DB.
  """

  def _check_reserved_without_database(self, handle_name_lowercase):
    """Check only static reserved patterns (skip DB lookup)."""
    # Check prefix patterns
    for prefix in handle_service._RESERVED_PREFIX_PATTERNS:
      if handle_name_lowercase.startswith(prefix.lower()):
        return True, f"Handles starting with '{prefix}' are reserved"
    # Check exact names
    if handle_name_lowercase in handle_service._RESERVED_EXACT_NAMES:
      return True, f"'{handle_name_lowercase}' is a reserved name"
    return False, None

  # --- Prefix: '1id' ---

  def test_1id_prefix_reserved(self):
    is_reserved, reason = self._check_reserved_without_database("1id-something")
    assert is_reserved is True

  def test_1id_exact_reserved(self):
    is_reserved, reason = self._check_reserved_without_database("1id")
    assert is_reserved is True

  def test_1idcom_reserved(self):
    is_reserved, reason = self._check_reserved_without_database("1idcom")
    assert is_reserved is True

  def test_1id123_reserved(self):
    is_reserved, reason = self._check_reserved_without_database("1id123")
    assert is_reserved is True

  # --- Exact match service names ---

  def test_admin_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("admin")
    assert is_reserved is True

  def test_root_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("root")
    assert is_reserved is True

  def test_support_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("support")
    assert is_reserved is True

  # --- Exact match sentinel values ---

  def test_null_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("null")
    assert is_reserved is True

  def test_undefined_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("undefined")
    assert is_reserved is True

  def test_true_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("true")
    assert is_reserved is True

  def test_false_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("false")
    assert is_reserved is True

  # --- DNS/RFC names ---

  def test_www_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("www")
    assert is_reserved is True

  def test_api_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("api")
    assert is_reserved is True

  def test_postmaster_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("postmaster")
    assert is_reserved is True

  def test_abuse_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("abuse")
    assert is_reserved is True

  # --- NOT reserved ---

  def test_clawdia_not_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("clawdia")
    assert is_reserved is False

  def test_chrisdrake_not_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("chrisdrake")
    assert is_reserved is False

  def test_bot9000_not_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("bot9000")
    assert is_reserved is False

  def test_ai_not_reserved(self):
    is_reserved, _ = self._check_reserved_without_database("ai")
    assert is_reserved is False


# ===================================================================
# 4. Pricing tier classification
# ===================================================================

class TestClassifyHandlePricingTier:
  """Tests for classify_handle_pricing_tier()."""

  def test_1_char(self):
    assert handle_service.classify_handle_pricing_tier("a") == "1char"

  def test_2_char(self):
    assert handle_service.classify_handle_pricing_tier("ai") == "2char"

  def test_3_char(self):
    assert handle_service.classify_handle_pricing_tier("bot") == "3char"

  def test_4_char(self):
    assert handle_service.classify_handle_pricing_tier("cool") == "4char"

  def test_5_char(self):
    assert handle_service.classify_handle_pricing_tier("tesla") == "5char"

  def test_6_char(self):
    assert handle_service.classify_handle_pricing_tier("clawdi") == "6plus"

  def test_7_char(self):
    assert handle_service.classify_handle_pricing_tier("clawdia") == "6plus"

  def test_63_char(self):
    assert handle_service.classify_handle_pricing_tier("a" * 63) == "6plus"


# ===================================================================
# 5. Annual fee lookups
# ===================================================================

class TestGetAnnualFeeCentsUsd:
  """Tests for get_annual_fee_cents_usd()."""

  def test_permanent_random_is_free(self):
    assert handle_service.get_annual_fee_cents_usd("permanent_random") == 0

  def test_vip_lifetime_is_free(self):
    assert handle_service.get_annual_fee_cents_usd("vip_lifetime") == 0

  def test_6plus_is_10_dollars(self):
    assert handle_service.get_annual_fee_cents_usd("6plus") == 1000

  def test_5char_is_50_dollars(self):
    assert handle_service.get_annual_fee_cents_usd("5char") == 5000

  def test_4char_is_200_dollars(self):
    assert handle_service.get_annual_fee_cents_usd("4char") == 20000

  def test_3char_is_500_dollars(self):
    assert handle_service.get_annual_fee_cents_usd("3char") == 50000

  def test_2char_is_1000_dollars(self):
    assert handle_service.get_annual_fee_cents_usd("2char") == 100000

  def test_1char_is_5000_dollars(self):
    assert handle_service.get_annual_fee_cents_usd("1char") == 500000

  def test_unknown_tier_raises(self):
    try:
      handle_service.get_annual_fee_cents_usd("nonexistent_tier")
      assert False, "Should have raised ValueError"
    except ValueError:
      pass


# ===================================================================
# 6. Multi-year discount calculation
# ===================================================================

class TestCalculateMultiYearTotalCentsUsd:
  """Tests for calculate_multi_year_total_cents_usd() -- the core pricing formula."""

  # --- Basic correctness ---

  def test_1_year_is_full_price(self):
    result = handle_service.calculate_multi_year_total_cents_usd(20000, 1)
    assert result == 20000  # $200

  def test_2_years_has_discount(self):
    result = handle_service.calculate_multi_year_total_cents_usd(20000, 2)
    # Year 1: 20000, Year 2: 20000 * 0.96 = 19200. Total = 39200
    assert result == 39200

  def test_3_years(self):
    result = handle_service.calculate_multi_year_total_cents_usd(20000, 3)
    # Year 1: 20000, Year 2: 19200, Year 3: 18432. Total = 57632.
    # Formula uses geometric series so floating point may round up by 1 cent.
    assert result in (57632, 57633)

  # --- The 50% floor ---

  def test_year_18_hits_floor(self):
    """Year 18 is the first year where the floor applies."""
    # At year 17: 0.96^16 = ~0.5204 (above floor)
    # At year 18: 0.96^17 = ~0.4996 (below floor -> clamped to 0.50)
    result_17 = handle_service.calculate_multi_year_total_cents_usd(20000, 17)
    result_18 = handle_service.calculate_multi_year_total_cents_usd(20000, 18)
    # The 18th year should cost exactly 50% of annual fee = 10000 cents
    difference_year_18_cost = result_18 - result_17
    assert difference_year_18_cost == 10000  # $100 (50% of $200)

  def test_year_25_still_at_floor(self):
    """Years 18-25 should all cost 50% of annual fee."""
    result_17 = handle_service.calculate_multi_year_total_cents_usd(20000, 17)
    result_25 = handle_service.calculate_multi_year_total_cents_usd(20000, 25)
    # Years 18-25 = 8 years at floor = 8 * 10000 = 80000
    assert result_25 == result_17 + 80000

  def test_100_years(self):
    result = handle_service.calculate_multi_year_total_cents_usd(20000, 100)
    # 17 years compounding + 83 years at floor
    result_17 = handle_service.calculate_multi_year_total_cents_usd(20000, 17)
    expected = result_17 + 83 * 10000
    assert result == expected

  # --- Every year costs money ---

  def test_every_year_costs_money(self):
    """The key invariant: every additional year increases the total."""
    annual_fee = 1000  # $10
    previous_total = 0
    for year in range(1, 101):
      total = handle_service.calculate_multi_year_total_cents_usd(annual_fee, year)
      assert total > previous_total, f"Year {year} did not increase total (was {previous_total}, got {total})"
      previous_total = total

  def test_no_year_costs_less_than_half(self):
    """No single year can cost less than 50% of the annual fee."""
    annual_fee = 20000  # $200
    half_fee = annual_fee * 0.5
    previous_total = 0
    for year in range(1, 201):
      total = handle_service.calculate_multi_year_total_cents_usd(annual_fee, year)
      year_cost = total - previous_total
      assert year_cost >= half_fee, (
        f"Year {year} cost ${year_cost / 100:.2f} which is less than "
        f"50% floor ${half_fee / 100:.2f}"
      )
      previous_total = total

  # --- Extreme values (smartypants agent stress test) ---

  def test_1000_years(self):
    result = handle_service.calculate_multi_year_total_cents_usd(1000, 1000)
    # 17 years compounding + 983 years at floor (500 each)
    assert result > 500000  # must be more than $5,000
    # Floor portion alone: 983 * 500 = 491500
    # Plus compounding portion: ~12520
    assert result > 500000

  def test_billion_years_does_not_overflow(self):
    """A billion years must not overflow, crash, or return nonsense."""
    result = handle_service.calculate_multi_year_total_cents_usd(1000, 1000000000)
    # Should be ~17 years compounding + 999999983 years at 500 cents each
    assert result > 0
    # Approximately: 999999983 * 500 = ~500 billion cents = $5 billion
    # This is correct: a billion years of a $10/year handle costs ~$5 billion

  def test_10_dollar_handle_1000_years_costs_real_money(self):
    """Verify the old formula's flaw is fixed: 1000yr of $10/yr handle != $250."""
    result = handle_service.calculate_multi_year_total_cents_usd(1000, 1000)
    # Old formula: $250 (25x annual). New formula: much more.
    assert result > 50000, f"1000 years of $10/yr should cost >> $500, got ${result / 100:.2f}"

  # --- Free handles ---

  def test_free_handle_0_annual_fee(self):
    result = handle_service.calculate_multi_year_total_cents_usd(0, 5)
    assert result == 0

  def test_free_handle_0_annual_fee_1000_years(self):
    result = handle_service.calculate_multi_year_total_cents_usd(0, 1000)
    assert result == 0

  # --- Input validation ---

  def test_zero_years_raises(self):
    try:
      handle_service.calculate_multi_year_total_cents_usd(1000, 0)
      assert False, "Should have raised ValueError"
    except ValueError:
      pass

  def test_negative_years_raises(self):
    try:
      handle_service.calculate_multi_year_total_cents_usd(1000, -1)
      assert False, "Should have raised ValueError"
    except ValueError:
      pass

  def test_float_years_raises(self):
    try:
      handle_service.calculate_multi_year_total_cents_usd(1000, 2.5)
      assert False, "Should have raised TypeError"
    except TypeError:
      pass

  def test_string_years_raises(self):
    try:
      handle_service.calculate_multi_year_total_cents_usd(1000, "5")
      assert False, "Should have raised TypeError"
    except TypeError:
      pass

  # --- Discount summary ---

  def test_discount_summary_1_year(self):
    summary = handle_service.calculate_multi_year_discount_summary(20000, 1)
    assert summary["total_cents_usd"] == 20000
    assert summary["full_price_cents_usd"] == 20000
    assert summary["savings_cents_usd"] == 0
    assert summary["years"] == 1

  def test_discount_summary_5_years(self):
    summary = handle_service.calculate_multi_year_discount_summary(20000, 5)
    assert summary["total_cents_usd"] < summary["full_price_cents_usd"]
    assert summary["savings_cents_usd"] > 0
    assert summary["years"] == 5

  def test_discount_summary_savings_are_positive(self):
    for years in [2, 5, 10, 25, 50]:
      summary = handle_service.calculate_multi_year_discount_summary(1000, years)
      assert summary["savings_cents_usd"] > 0, f"No savings at {years} years"

  def test_discount_summary_effective_per_year_is_positive(self):
    for years in [1, 5, 10, 50, 100]:
      summary = handle_service.calculate_multi_year_discount_summary(1000, years)
      assert summary["effective_per_year_cents_usd"] > 0


# ===================================================================
# 7. Constants verification
# ===================================================================

class TestDiscountConstants:
  """Verify the discount constants are sane."""

  def test_floor_year_k_is_17(self):
    """K should be 17 (ceil(ln(0.5) / ln(0.96)))."""
    assert handle_service._DISCOUNT_FLOOR_YEAR_K == 17

  def test_discount_rate_is_0_96(self):
    assert handle_service._DISCOUNT_RATE_PER_YEAR == 0.96

  def test_floor_fraction_is_0_50(self):
    assert handle_service._DISCOUNT_FLOOR_FRACTION == 0.50

  def test_rate_at_year_17_is_above_floor(self):
    """Year 17 should still be above the 50% floor."""
    rate = 0.96 ** (17 - 1)  # 0.96^16
    assert rate > 0.50

  def test_rate_at_year_18_is_below_floor(self):
    """Year 18's raw rate should be below 50% (triggering the floor)."""
    rate = 0.96 ** (18 - 1)  # 0.96^17
    assert rate < 0.50


# ===================================================================
# Run with pytest
# ===================================================================

if __name__ == "__main__":
  import pytest
  pytest.main([__file__, "-v"])
