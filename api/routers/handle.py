"""
1id.com -- Handle Router

Handle management endpoints:
  GET  /api/v1/handle/{name}     -- check handle availability + pricing
"""

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from services import handle_service

router = APIRouter(prefix="/api/v1/handle", tags=["handles"])


@router.get("/{name}")
async def check_handle_availability_and_pricing(
  name: str,
  years: int = Query(default=1, ge=1, le=999999999, description="Number of years for multi-year pricing"),
):
  """
  Check handle availability, pricing, and multi-year discount.
  Public endpoint, no auth required.

  Returns:
    - Availability status (available, active, expired, payment_dispute, retired)
    - Pricing tier and annual fee
    - Multi-year discount breakdown (if years > 1)
    - Reserved status (if the handle is reserved and cannot be registered)
    - Validation errors (if the handle name is invalid)
  """
  # Normalize input: strip @, preserve display form, lowercase for lookup
  handle_name_lowercase, handle_name_display = handle_service.normalize_handle_input(name)

  # Validate the handle name (DNS-compatible rules)
  is_valid, validation_error_message = handle_service.validate_handle_name(handle_name_lowercase)
  if not is_valid:
    return JSONResponse(
      status_code=400,
      content={
        "ok": False,
        "data": None,
        "error": {"code": "HANDLE_INVALID", "message": validation_error_message},
      },
    )

  # Check if reserved (static patterns + database)
  is_reserved, reserved_reason = handle_service.check_handle_is_reserved(handle_name_lowercase)
  if is_reserved:
    return JSONResponse(
      status_code=200,
      content={
        "ok": True,
        "data": {
          "handle": f"@{handle_name_display}",
          "handle_normalized": handle_name_lowercase,
          "status": "reserved",
          "reserved_reason": reserved_reason,
        },
        "error": None,
      },
    )

  # Check availability in handles table
  availability_status = handle_service.check_handle_availability(handle_name_lowercase)

  # Get pricing info
  pricing_tier = handle_service.classify_handle_pricing_tier(handle_name_lowercase)
  annual_fee_cents_usd = handle_service.get_annual_fee_cents_usd(pricing_tier)
  pricing_tier_label = handle_service.get_pricing_tier_label(pricing_tier)

  # Calculate multi-year discount
  discount_summary = handle_service.calculate_multi_year_discount_summary(
    annual_fee_cents_usd, years
  )

  return JSONResponse(
    status_code=200,
    content={
      "ok": True,
      "data": {
        "handle": f"@{handle_name_display}",
        "handle_normalized": handle_name_lowercase,
        "status": availability_status,
        "pricing": {
          "tier": pricing_tier,
          "tier_label": pricing_tier_label,
          "annual_fee_cents_usd": annual_fee_cents_usd,
          "annual_fee_usd": annual_fee_cents_usd / 100,
        },
        "multi_year": {
          "years": discount_summary["years"],
          "total_cents_usd": discount_summary["total_cents_usd"],
          "total_usd": discount_summary["total_cents_usd"] / 100,
          "full_price_cents_usd": discount_summary["full_price_cents_usd"],
          "full_price_usd": discount_summary["full_price_cents_usd"] / 100,
          "savings_cents_usd": discount_summary["savings_cents_usd"],
          "savings_usd": discount_summary["savings_cents_usd"] / 100,
          "effective_per_year_cents_usd": discount_summary["effective_per_year_cents_usd"],
          "effective_per_year_usd": discount_summary["effective_per_year_cents_usd"] / 100,
        },
      },
      "error": None,
    },
  )
