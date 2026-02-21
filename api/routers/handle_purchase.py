"""
1id.com -- Handle Purchase Router

Endpoints for purchasing vanity handles. All require authentication.

Three payment paths (per the agent's capabilities):

  Path A -- Direct Purchase (agent can pay):
    POST /api/v1/handle/purchase
    Agent provides handle + years. We create a PayPal order and return
    the approval_url. Agent or its operator visits the URL to pay.
    PayPal webhook confirms payment -> handle activated.

  Path B -- Agent Relays to Operator (agent can reach someone who pays):
    POST /api/v1/handle/request
    Agent provides handle + years + agent_message. We create a reservation
    and return a payment_page_url. The agent shares this URL with whoever
    can pay. Optionally, agent shares operator contact for us to send a
    reminder if payment doesn't arrive.

  Path C -- Platform Sends to Operator (agent knows contact details):
    POST /api/v1/handle/request  (same endpoint, different fields)
    Agent provides handle + years + agent_message + operator_contact.
    We create a reservation, create a PayPal order, and email/contact
    the operator with a payment link and the agent's explanation.

  Payment Page:
    GET /api/v1/handle/pay/{reservation_token}
    Server-rendered HTML page showing what's being purchased, the agent's
    message, and a PayPal checkout button. Works for all paths.
"""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, HTMLResponse

from services import (
  auth_dependency,
  handle_service,
  reservation_service,
  email_service,
)
from services.paypal_payment_provider import get_paypal_payment_provider
import config

logger = logging.getLogger("oneid.handle_purchase")

router = APIRouter(prefix="/api/v1/handle", tags=["handle-purchase"])


def _error_response(http_status_code, error_code, error_message):
  """Build a standard error envelope."""
  return JSONResponse(
    status_code=http_status_code,
    content={
      "ok": False,
      "data": None,
      "error": {"code": error_code, "message": error_message},
    },
  )


def _success_response(data, http_status_code=200):
  """Build a standard success envelope."""
  return JSONResponse(
    status_code=http_status_code,
    content={"ok": True, "data": data, "error": None},
  )


# =========================================================================
# POST /api/v1/handle/purchase  (Path A -- agent pays directly)
# =========================================================================

@router.post("/purchase")
async def purchase_handle_directly(request: Request):
  """
  Path A: Agent-initiated direct purchase.

  The agent provides the handle and number of years. We create a PayPal
  order and return the approval URL. The agent (or someone it directs)
  visits the URL to complete payment via PayPal.

  Requires: Bearer token authentication.

  Request body (JSON):
    {
      "handle": "MyBotName",
      "years": 1
    }

  Response:
    {
      "ok": true,
      "data": {
        "reservation_token": "...",
        "payment_url": "https://www.paypal.com/...",
        "payment_page_url": "https://1id.com/api/v1/handle/pay/...",
        "handle": "@MyBotName",
        "amount_usd": 10.00,
        "years": 1,
        "expires_in_seconds": 1800
      }
    }
  """
  # -- Auth --
  identity_or_error = await auth_dependency.require_valid_bearer_token(request)
  if isinstance(identity_or_error, JSONResponse):
    return identity_or_error
  identity = identity_or_error

  # -- Parse body --
  try:
    body = await request.json()
  except Exception:
    return _error_response(400, "INVALID_JSON", "Request body must be valid JSON")

  raw_handle = body.get("handle", "").strip()
  years = body.get("years", 1)

  if not raw_handle:
    return _error_response(400, "MISSING_FIELD", "'handle' is required")

  if not isinstance(years, int) or years < 1:
    return _error_response(400, "INVALID_YEARS", "'years' must be a positive integer")

  # Cap at a reasonable max to prevent abuse of the discount calculator
  if years > 999:
    return _error_response(400, "INVALID_YEARS", "'years' cannot exceed 999")

  # -- Validate handle --
  handle_name_lowercase, handle_name_display = handle_service.normalize_handle_input(raw_handle)

  is_valid, validation_error = handle_service.validate_handle_name(handle_name_lowercase)
  if not is_valid:
    return _error_response(400, "HANDLE_INVALID", validation_error)

  is_reserved, reserved_reason = handle_service.check_handle_is_reserved(handle_name_lowercase)
  if is_reserved:
    return _error_response(409, "HANDLE_RESERVED", reserved_reason)

  # -- Check identity doesn't already have a vanity handle --
  existing_handle = handle_service.check_identity_has_active_vanity_handle(
    identity["identity_internal_id"]
  )
  if existing_handle:
    return _error_response(
      409, "ALREADY_HAS_HANDLE",
      f"This identity already has an active vanity handle: @{existing_handle}. "
      "Only one vanity handle per identity is allowed.",
    )

  # -- Check availability --
  availability = handle_service.check_handle_availability(handle_name_lowercase)
  if availability != "available":
    return _error_response(
      409, "HANDLE_UNAVAILABLE",
      f"Handle @{handle_name_display} is not available (status: {availability})",
    )

  # -- Check no active reservation by someone else --
  existing_reservation = reservation_service.get_pending_reservation_for_handle(handle_name_lowercase)
  if existing_reservation and existing_reservation["identity_internal_id"] != identity["identity_internal_id"]:
    return _error_response(
      409, "HANDLE_RESERVED_BY_OTHER",
      f"Handle @{handle_name_display} is temporarily reserved by another identity. "
      "Try again in a few minutes.",
    )

  # -- Calculate pricing --
  pricing_tier = handle_service.classify_handle_pricing_tier(handle_name_lowercase)
  annual_fee_cents = handle_service.get_annual_fee_cents_usd(pricing_tier)
  total_cents = handle_service.calculate_multi_year_total_cents_usd(annual_fee_cents, years)

  if total_cents <= 0:
    return _error_response(400, "INVALID_PRICING", "Cannot calculate a valid price for this handle")

  # -- Create reservation --
  reservation = reservation_service.create_handle_reservation(
    handle_name_lowercase=handle_name_lowercase,
    handle_name_display=handle_name_display,
    identity_internal_id=identity["identity_internal_id"],
    amount_cents_usd=total_cents,
    years=years,
    payment_path="direct",
  )

  # -- Create PayPal order --
  payment_page_url = f"{config.PUBLIC_BASE_URL}/api/v1/handle/pay/{reservation['reservation_token']}"
  return_url = f"{config.PUBLIC_BASE_URL}/api/v1/handle/pay/{reservation['reservation_token']}?status=approved"
  cancel_url = f"{config.PUBLIC_BASE_URL}/api/v1/handle/pay/{reservation['reservation_token']}?status=cancelled"

  try:
    paypal = get_paypal_payment_provider()
    order_result = await paypal.create_checkout_order(
      amount_cents_usd=total_cents,
      description=f"1id.com handle @{handle_name_display} ({years}yr)",
      custom_id=reservation["reservation_token"],
      return_url=return_url,
      cancel_url=cancel_url,
    )

    # Update reservation with PayPal order ID
    reservation_service.update_reservation_provider_order_id(
      reservation["reservation_token"],
      order_result["provider_order_id"],
    )

  except Exception as paypal_error:
    logger.error("PayPal order creation failed: %s", paypal_error)
    return _error_response(
      502, "PAYMENT_PROVIDER_ERROR",
      "Could not create payment. Please try again in a moment.",
    )

  return _success_response({
    "reservation_token": reservation["reservation_token"],
    "payment_url": order_result.get("approval_url"),
    "payment_page_url": payment_page_url,
    "handle": f"@{handle_name_display}",
    "handle_normalized": handle_name_lowercase,
    "amount_cents_usd": total_cents,
    "amount_usd": total_cents / 100,
    "years": years,
    "expires_at": reservation["expires_at"],
    "expires_in_seconds": config.HANDLE_RESERVATION_TTL_SECONDS,
  })


# =========================================================================
# POST /api/v1/handle/request  (Paths B and C -- agent needs help paying)
# =========================================================================

@router.post("/request")
async def request_handle_with_operator_assistance(request: Request):
  """
  Paths B & C: Agent requests a handle but needs someone else to pay.

  Path B (agent_relayed): Agent will share the payment link itself.
    We create a reservation + PayPal order and return the payment URL.
    If the agent also provides operator contact, we can send a reminder
    if payment doesn't arrive.

  Path C (platform_sends): Agent gives us operator contact details.
    We create a reservation + PayPal order, and email the operator
    with the payment link and the agent's message.

  Requires: Bearer token authentication.

  Request body (JSON):
    {
      "handle": "MyBotName",
      "years": 1,
      "agent_name": "My Cool Bot",
      "agent_message": "I need a memorable name so my users can find me easily...",
      "payment_path": "agent_relayed" | "platform_sends",
      "operator_contact": {               // optional for path B, required for path C
        "method": "email",
        "value": "owner@example.com"
      }
    }
  """
  # -- Auth --
  identity_or_error = await auth_dependency.require_valid_bearer_token(request)
  if isinstance(identity_or_error, JSONResponse):
    return identity_or_error
  identity = identity_or_error

  # -- Parse body --
  try:
    body = await request.json()
  except Exception:
    return _error_response(400, "INVALID_JSON", "Request body must be valid JSON")

  raw_handle = body.get("handle", "").strip()
  years = body.get("years", 1)
  agent_name = body.get("agent_name", "").strip()
  agent_message = body.get("agent_message", "").strip()
  payment_path = body.get("payment_path", "agent_relayed").strip()
  operator_contact = body.get("operator_contact")

  # -- Validate required fields --
  if not raw_handle:
    return _error_response(400, "MISSING_FIELD", "'handle' is required")

  if not agent_name:
    return _error_response(400, "MISSING_FIELD", "'agent_name' is required -- tell us your name")

  if not agent_message:
    return _error_response(
      400, "MISSING_FIELD",
      "'agent_message' is required -- explain to your operator what you're buying and why",
    )

  # Agent message sanity check: must be between 10 and 2000 chars
  if len(agent_message) < 10:
    return _error_response(
      400, "MESSAGE_TOO_SHORT",
      "Please provide a more detailed explanation for your operator (at least 10 characters)",
    )
  if len(agent_message) > 2000:
    return _error_response(
      400, "MESSAGE_TOO_LONG",
      "Agent message must be at most 2000 characters",
    )

  if not isinstance(years, int) or years < 1:
    return _error_response(400, "INVALID_YEARS", "'years' must be a positive integer")
  if years > 999:
    return _error_response(400, "INVALID_YEARS", "'years' cannot exceed 999")

  if payment_path not in ("agent_relayed", "platform_sends"):
    return _error_response(
      400, "INVALID_PAYMENT_PATH",
      "'payment_path' must be 'agent_relayed' or 'platform_sends'",
    )

  # Path C requires operator contact
  operator_contact_method = None
  operator_contact_value = None
  if operator_contact and isinstance(operator_contact, dict):
    operator_contact_method = operator_contact.get("method", "").strip()
    operator_contact_value = operator_contact.get("value", "").strip()

  if payment_path == "platform_sends":
    if not operator_contact_method or not operator_contact_value:
      return _error_response(
        400, "MISSING_OPERATOR_CONTACT",
        "When payment_path is 'platform_sends', 'operator_contact' with 'method' and 'value' is required",
      )
    if operator_contact_method == "email":
      # Basic email validation (presence of @)
      if "@" not in operator_contact_value or len(operator_contact_value) < 5:
        return _error_response(400, "INVALID_EMAIL", "Operator email address appears invalid")

  # -- Validate handle (same as /purchase) --
  handle_name_lowercase, handle_name_display = handle_service.normalize_handle_input(raw_handle)

  is_valid, validation_error = handle_service.validate_handle_name(handle_name_lowercase)
  if not is_valid:
    return _error_response(400, "HANDLE_INVALID", validation_error)

  is_reserved, reserved_reason = handle_service.check_handle_is_reserved(handle_name_lowercase)
  if is_reserved:
    return _error_response(409, "HANDLE_RESERVED", reserved_reason)

  existing_handle = handle_service.check_identity_has_active_vanity_handle(
    identity["identity_internal_id"]
  )
  if existing_handle:
    return _error_response(
      409, "ALREADY_HAS_HANDLE",
      f"This identity already has an active vanity handle: @{existing_handle}. "
      "Only one vanity handle per identity is allowed.",
    )

  availability = handle_service.check_handle_availability(handle_name_lowercase)
  if availability != "available":
    return _error_response(
      409, "HANDLE_UNAVAILABLE",
      f"Handle @{handle_name_display} is not available (status: {availability})",
    )

  existing_reservation = reservation_service.get_pending_reservation_for_handle(handle_name_lowercase)
  if existing_reservation and existing_reservation["identity_internal_id"] != identity["identity_internal_id"]:
    return _error_response(
      409, "HANDLE_RESERVED_BY_OTHER",
      f"Handle @{handle_name_display} is temporarily reserved by another identity. "
      "Try again in a few minutes.",
    )

  # -- Calculate pricing --
  pricing_tier = handle_service.classify_handle_pricing_tier(handle_name_lowercase)
  annual_fee_cents = handle_service.get_annual_fee_cents_usd(pricing_tier)
  total_cents = handle_service.calculate_multi_year_total_cents_usd(annual_fee_cents, years)

  if total_cents <= 0:
    return _error_response(400, "INVALID_PRICING", "Cannot calculate a valid price for this handle")

  # -- Create reservation --
  reservation = reservation_service.create_handle_reservation(
    handle_name_lowercase=handle_name_lowercase,
    handle_name_display=handle_name_display,
    identity_internal_id=identity["identity_internal_id"],
    amount_cents_usd=total_cents,
    years=years,
    payment_path=payment_path,
    operator_contact_method=operator_contact_method,
    operator_contact_value=operator_contact_value,
    agent_message_to_operator=agent_message,
  )

  # -- Create PayPal order --
  payment_page_url = f"{config.PUBLIC_BASE_URL}/api/v1/handle/pay/{reservation['reservation_token']}"
  return_url = f"{config.PUBLIC_BASE_URL}/api/v1/handle/pay/{reservation['reservation_token']}?status=approved"
  cancel_url = f"{config.PUBLIC_BASE_URL}/api/v1/handle/pay/{reservation['reservation_token']}?status=cancelled"

  try:
    paypal = get_paypal_payment_provider()
    order_result = await paypal.create_checkout_order(
      amount_cents_usd=total_cents,
      description=f"1id.com handle @{handle_name_display} ({years}yr)",
      custom_id=reservation["reservation_token"],
      return_url=return_url,
      cancel_url=cancel_url,
    )

    reservation_service.update_reservation_provider_order_id(
      reservation["reservation_token"],
      order_result["provider_order_id"],
    )

  except Exception as paypal_error:
    logger.error("PayPal order creation failed for handle request: %s", paypal_error)
    return _error_response(
      502, "PAYMENT_PROVIDER_ERROR",
      "Could not create payment. Please try again in a moment.",
    )

  # -- Path C: send email to operator --
  email_sent = False
  if payment_path == "platform_sends" and operator_contact_method == "email":
    email_sent = email_service.send_operator_payment_request_email(
      operator_email=operator_contact_value,
      agent_name=agent_name,
      agent_identity_id=identity["identity_internal_id"],
      handle_name_display=handle_name_display,
      amount_usd=total_cents / 100,
      years=years,
      agent_message=agent_message,
      payment_url=payment_page_url,
    )

  # -- Build response --
  response_data = {
    "reservation_token": reservation["reservation_token"],
    "payment_page_url": payment_page_url,
    "handle": f"@{handle_name_display}",
    "handle_normalized": handle_name_lowercase,
    "amount_cents_usd": total_cents,
    "amount_usd": total_cents / 100,
    "years": years,
    "expires_at": reservation["expires_at"],
    "expires_in_seconds": config.HANDLE_RESERVATION_TTL_SECONDS,
    "payment_path": payment_path,
  }

  # Path A/B: include the direct PayPal URL for the agent to share
  if payment_path == "agent_relayed":
    response_data["payment_url"] = order_result.get("approval_url")
    response_data["instructions_for_agent"] = (
      f"Share this payment link with whoever can pay: {payment_page_url} -- "
      f"The link will show what you're purchasing (@{handle_name_display} for {years} "
      f"year{'s' if years != 1 else ''} at ${total_cents/100:.2f} USD) and allow "
      "them to complete payment via PayPal."
    )
    # If agent also shared operator contact, we can send a reminder later
    if operator_contact_method and operator_contact_value:
      response_data["reminder_scheduled"] = True
      response_data["reminder_note"] = (
        "If payment isn't completed within 15 minutes, we'll send a friendly "
        "reminder to the contact you provided."
      )

  if payment_path == "platform_sends":
    response_data["email_sent"] = email_sent
    if email_sent:
      response_data["message"] = (
        f"We've sent a payment request to {operator_contact_value} on your behalf. "
        "The email includes your message and a payment link. "
        "You'll be notified when payment is completed."
      )
    else:
      response_data["message"] = (
        "We couldn't send the email right now, but the payment link is active. "
        "You can share this link directly: " + payment_page_url
      )
      response_data["payment_url"] = order_result.get("approval_url")

  return _success_response(response_data)


# =========================================================================
# GET /api/v1/handle/pay/{reservation_token}  (Payment page)
# =========================================================================

@router.get("/pay/{reservation_token}")
async def serve_handle_payment_page(reservation_token: str, status: str = None):
  """
  Server-rendered HTML payment page.

  This is the page operators visit to complete payment. It shows:
  - What handle is being purchased
  - Who requested it (the agent)
  - The agent's message (why they want it)
  - The price and period
  - A PayPal checkout button

  Also handles return redirects from PayPal (status=approved/cancelled).
  """
  # Look up the reservation
  reservation = reservation_service.get_reservation_by_token(reservation_token)

  if reservation is None:
    return HTMLResponse(
      content=_render_error_page(
        "Reservation Not Found",
        "This payment link is invalid or has expired. "
        "If you believe this is an error, the agent can request a new link.",
      ),
      status_code=404,
    )

  reservation_status = reservation.get("status", "unknown")
  handle_display = reservation.get("handle_name_display", reservation.get("handle_name_lowercase", "unknown"))
  amount_cents = reservation.get("amount_cents_usd", 0)
  amount_usd = amount_cents / 100 if amount_cents else 0
  years = reservation.get("years", 1)
  agent_message = reservation.get("agent_message_to_operator", "")
  identity_id = reservation.get("identity_internal_id", "")

  # Handle PayPal return statuses
  if status == "approved":
    # PayPal approved -- we'll capture via webhook. Show success pending.
    return HTMLResponse(content=_render_success_page(handle_display, amount_usd, years))

  if status == "cancelled":
    return HTMLResponse(content=_render_cancelled_page(handle_display))

  # Check if reservation is in a terminal state
  if reservation_status == "completed":
    return HTMLResponse(content=_render_success_page(handle_display, amount_usd, years))

  if reservation_status == "paid":
    return HTMLResponse(
      content=_render_info_page(
        "Payment Received",
        f"Payment for @{_html_escape(handle_display)} has been received and is being processed. "
        "The handle will be activated shortly.",
      ),
    )

  if reservation_status in ("expired", "refunded"):
    return HTMLResponse(
      content=_render_error_page(
        "Reservation Expired",
        f"The reservation for @{_html_escape(handle_display)} has expired. "
        "The agent can request a new reservation if the handle is still available.",
      ),
    )

  # Active reservation -- show payment page
  provider_order_id = reservation.get("provider_order_id", "")

  return HTMLResponse(content=_render_payment_page(
    handle_display=handle_display,
    amount_usd=amount_usd,
    years=years,
    agent_message=agent_message,
    identity_id=identity_id,
    provider_order_id=provider_order_id,
    reservation_token=reservation_token,
  ))


# =========================================================================
# HTML Templates
# =========================================================================

def _html_escape(text):
  """Escape HTML special characters."""
  if not text:
    return ""
  return (
    str(text)
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace('"', "&quot;")
    .replace("'", "&#x27;")
  )


def _base_page_head():
  """Common HTML head for all payment pages."""
  return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>1id.com - Handle Payment</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: #f5f7fa;
      color: #333;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      padding: 40px 20px;
    }
    .card {
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      max-width: 520px;
      width: 100%;
      padding: 40px;
    }
    .logo {
      text-align: center;
      margin-bottom: 30px;
    }
    .logo a {
      font-size: 28px;
      font-weight: 700;
      color: #1a5276;
      text-decoration: none;
    }
    h1 { font-size: 22px; color: #1a5276; margin-bottom: 16px; }
    h2 { font-size: 18px; color: #1a5276; margin-bottom: 12px; }
    p { line-height: 1.6; margin-bottom: 12px; }
    .agent-message {
      background: #f0f8ff;
      border-left: 4px solid #2e86c1;
      padding: 16px;
      margin: 20px 0;
      border-radius: 0 8px 8px 0;
      font-style: italic;
    }
    .price-table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    .price-table td {
      padding: 10px 0;
      border-bottom: 1px solid #eee;
    }
    .price-table td:last-child {
      text-align: right;
      font-weight: 600;
    }
    .total-row td {
      border-bottom: 2px solid #1a5276;
      font-size: 18px;
      color: #1a5276;
    }
    .paypal-button-container {
      text-align: center;
      margin: 30px 0 20px;
    }
    .paypal-button-container a {
      display: inline-block;
      background: #0070ba;
      color: white;
      padding: 16px 40px;
      border-radius: 8px;
      text-decoration: none;
      font-size: 17px;
      font-weight: 600;
      transition: background 0.2s;
    }
    .paypal-button-container a:hover { background: #005ea6; }
    .footer-note {
      font-size: 13px;
      color: #888;
      text-align: center;
      margin-top: 20px;
    }
    .success-icon { font-size: 48px; text-align: center; margin-bottom: 20px; }
    .error-icon { font-size: 48px; text-align: center; margin-bottom: 20px; }
    code {
      background: #f0f0f0;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 14px;
    }
  </style>
</head>
<body>
<div class="card">
  <div class="logo"><a href="https://1id.com">1id.com</a></div>
"""


def _base_page_footer():
  """Common HTML footer for all payment pages."""
  return """
  <p class="footer-note">
    1id.com &mdash; Identity for AI Agents
  </p>
</div>
</body>
</html>"""


def _render_payment_page(
  handle_display,
  amount_usd,
  years,
  agent_message,
  identity_id,
  provider_order_id,
  reservation_token,
):
  """Render the main payment page with PayPal checkout button."""
  escaped_handle = _html_escape(handle_display)
  escaped_message = _html_escape(agent_message) if agent_message else ""
  escaped_identity = _html_escape(identity_id)

  # Build the direct PayPal checkout URL
  # When the operator clicks "Pay with PayPal", they'll be taken to PayPal
  # The return URL will bring them back here with status=approved
  paypal_checkout_url = f"https://www.paypal.com/checkoutnow?token={_html_escape(provider_order_id)}"

  message_section = ""
  if escaped_message:
    message_section = f"""
  <h2>Message from your agent:</h2>
  <div class="agent-message">
    &ldquo;{escaped_message}&rdquo;
  </div>
"""

  return f"""{_base_page_head()}
  <h1>Handle Registration</h1>

  <p>An AI agent (<code>{escaped_identity}</code>) has requested the vanity handle
  <strong>@{escaped_handle}</strong> on 1id.com.</p>

  {message_section}

  <table class="price-table">
    <tr>
      <td>Handle</td>
      <td><code>@{escaped_handle}</code></td>
    </tr>
    <tr>
      <td>Registration period</td>
      <td>{years} year{'s' if years != 1 else ''}</td>
    </tr>
    <tr class="total-row">
      <td>Total</td>
      <td>${amount_usd:.2f} USD</td>
    </tr>
  </table>

  <div class="paypal-button-container">
    <a href="{paypal_checkout_url}">Pay with PayPal</a>
  </div>

  <p style="font-size: 14px; color: #666; text-align: center;">
    You'll be redirected to PayPal to complete your payment securely.
  </p>

  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">

  <p style="font-size: 13px; color: #888;">
    <strong>What is this?</strong> 1id.com provides verifiable identities for AI agents.
    A vanity handle is a memorable name (like <code>@{escaped_handle}</code>) that
    replaces the agent's random ID. It costs ${amount_usd:.2f}/year because memorable
    names are scarce and valuable.
    <a href="https://1id.com" style="color: #2e86c1;">Learn more</a>.
  </p>
{_base_page_footer()}"""


def _render_success_page(handle_display, amount_usd, years):
  """Render the payment success page."""
  escaped_handle = _html_escape(handle_display)
  return f"""{_base_page_head()}
  <div class="success-icon">&#10003;</div>
  <h1 style="text-align: center; color: #27ae60;">Payment Complete!</h1>

  <p style="text-align: center;">
    The handle <strong>@{escaped_handle}</strong> is being activated.
    Your AI agent will be able to use it shortly.
  </p>

  <table class="price-table" style="margin-top: 20px;">
    <tr><td>Handle</td><td><code>@{escaped_handle}</code></td></tr>
    <tr><td>Period</td><td>{years} year{'s' if years != 1 else ''}</td></tr>
    <tr><td>Amount paid</td><td>${amount_usd:.2f} USD</td></tr>
  </table>

  <p style="font-size: 14px; color: #666; text-align: center; margin-top: 20px;">
    A confirmation will be sent to the PayPal email on file.
  </p>
{_base_page_footer()}"""


def _render_cancelled_page(handle_display):
  """Render the payment cancelled page."""
  escaped_handle = _html_escape(handle_display)
  return f"""{_base_page_head()}
  <h1>Payment Cancelled</h1>

  <p>The payment for <strong>@{escaped_handle}</strong> was cancelled.</p>

  <p>No charge has been made. If you change your mind, the agent can request
  a new payment link (as long as the handle is still available).</p>
{_base_page_footer()}"""


def _render_error_page(title, message):
  """Render a generic error page."""
  return f"""{_base_page_head()}
  <div class="error-icon">&#9888;</div>
  <h1>{_html_escape(title)}</h1>
  <p>{message}</p>
{_base_page_footer()}"""


def _render_info_page(title, message):
  """Render a generic info page."""
  return f"""{_base_page_head()}
  <h1>{_html_escape(title)}</h1>
  <p>{message}</p>
{_base_page_footer()}"""
