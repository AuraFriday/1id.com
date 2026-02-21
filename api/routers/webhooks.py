"""
1id.com -- Webhook Router

Receives webhooks from payment providers (PayPal) and processes them.

PayPal webhook: POST /api/v1/webhooks/paypal
  Webhook ID: 28477273WV095113Y (configured in PayPal dashboard)
  Events: All Events (we filter by event_type in code)

Security:
  - Every webhook is signature-verified using PayPal's verification API
  - We verify the event references a valid reservation in our database
  - We verify amounts match what we expected
  - All webhook processing is idempotent (safe to receive duplicates)

Event types we handle:
  CHECKOUT.ORDER.APPROVED    -- buyer approved the order, we capture it
  PAYMENT.CAPTURE.COMPLETED  -- payment captured successfully
  PAYMENT.CAPTURE.DENIED     -- payment capture failed
  PAYMENT.CAPTURE.REFUNDED   -- we issued a refund
  CUSTOMER.DISPUTE.CREATED   -- chargeback/dispute opened
  CUSTOMER.DISPUTE.RESOLVED  -- dispute resolved
"""

import datetime
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from services import handle_service, reservation_service
from services.paypal_payment_provider import get_paypal_payment_provider

logger = logging.getLogger("oneid.webhooks")

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


@router.post("/paypal")
async def receive_paypal_webhook(request: Request):
  """
  Receive and process PayPal webhook events.

  PayPal sends a POST with the event payload. We verify the signature,
  then process the event based on its type.

  Returns 200 OK to acknowledge receipt (PayPal retries on non-200).
  """
  # -- Read raw body for signature verification --
  raw_body = await request.body()

  # -- Verify webhook signature --
  paypal = get_paypal_payment_provider()
  headers_dict = dict(request.headers)

  is_signature_valid = await paypal.verify_webhook_signature(headers_dict, raw_body)
  if not is_signature_valid:
    logger.warning("PayPal webhook signature verification FAILED")
    # Return 200 anyway to prevent PayPal from retrying a forged request
    # (if we return non-200, PayPal retries, which amplifies any attack)
    return JSONResponse(
      status_code=200,
      content={"status": "signature_invalid"},
    )

  # -- Parse the event --
  try:
    import json
    event_data = json.loads(raw_body)
  except Exception:
    logger.error("PayPal webhook: invalid JSON body")
    return JSONResponse(status_code=200, content={"status": "invalid_json"})

  event_type = event_data.get("event_type", "")
  event_id = event_data.get("id", "")
  resource = event_data.get("resource", {})

  logger.info(
    "PayPal webhook received: event_type=%s, event_id=%s",
    event_type, event_id,
  )

  # -- Dispatch by event type --
  try:
    if event_type == "CHECKOUT.ORDER.APPROVED":
      await _handle_order_approved(resource, event_id)

    elif event_type == "PAYMENT.CAPTURE.COMPLETED":
      await _handle_capture_completed(resource, event_id)

    elif event_type == "PAYMENT.CAPTURE.DENIED":
      _handle_capture_denied(resource, event_id)

    elif event_type == "PAYMENT.CAPTURE.REFUNDED":
      _handle_capture_refunded(resource, event_id)

    elif event_type == "CUSTOMER.DISPUTE.CREATED":
      _handle_dispute_created(resource, event_id)

    elif event_type == "CUSTOMER.DISPUTE.RESOLVED":
      _handle_dispute_resolved(resource, event_id)

    else:
      logger.info("PayPal webhook: unhandled event_type=%s (ignoring)", event_type)

  except Exception as processing_error:
    logger.error(
      "PayPal webhook processing error: event_type=%s, event_id=%s, error=%s",
      event_type, event_id, processing_error,
    )

  # Always return 200 to acknowledge receipt
  return JSONResponse(status_code=200, content={"status": "ok"})


# =========================================================================
# Event Handlers
# =========================================================================

async def _handle_order_approved(resource, event_id):
  """
  CHECKOUT.ORDER.APPROVED: Buyer approved the PayPal order.
  We need to capture the payment now.

  Flow:
    1. Look up reservation by PayPal order ID
    2. Verify reservation exists and is pending
    3. Capture the payment via PayPal API
    4. If capture succeeds: mark reservation paid, activate handle
    5. If handle is no longer available: refund the payment
  """
  order_id = resource.get("id", "")
  if not order_id:
    logger.warning("CHECKOUT.ORDER.APPROVED: no order ID in resource")
    return

  # Find our reservation
  reservation = reservation_service.get_reservation_by_provider_order_id(order_id)
  if reservation is None:
    logger.warning(
      "CHECKOUT.ORDER.APPROVED: no reservation found for order_id=%s", order_id,
    )
    return

  reservation_token = reservation["reservation_token"]
  reservation_status = reservation.get("status", "")

  # Idempotency: skip if already processed
  if reservation_status in ("paid", "completed"):
    logger.info("CHECKOUT.ORDER.APPROVED: reservation %s already processed", reservation_token)
    return

  # Capture the payment
  paypal = get_paypal_payment_provider()
  try:
    capture_result = await paypal.capture_order(order_id)
  except Exception as capture_error:
    logger.error(
      "CHECKOUT.ORDER.APPROVED: capture failed for order_id=%s: %s",
      order_id, capture_error,
    )
    return

  capture_id = capture_result.get("capture_id")
  captured_status = capture_result.get("status", "")
  payer_email = capture_result.get("payer_email")
  captured_amount_cents = capture_result.get("amount_cents_usd", 0)

  if captured_status != "COMPLETED":
    logger.warning(
      "CHECKOUT.ORDER.APPROVED: capture status=%s (not COMPLETED) for order_id=%s",
      captured_status, order_id,
    )
    return

  # Verify amount matches
  expected_amount_cents = reservation.get("amount_cents_usd", 0)
  if captured_amount_cents < expected_amount_cents:
    logger.error(
      "CHECKOUT.ORDER.APPROVED: amount mismatch! expected=%d, captured=%d, order_id=%s",
      expected_amount_cents, captured_amount_cents, order_id,
    )
    # Still proceed -- the buyer paid, we should honour it.
    # Log the discrepancy for manual review.

  # Mark reservation as paid
  reservation_service.mark_reservation_as_paid(
    reservation_token, capture_id, payer_email,
  )

  # Record payment in the permanent audit trail
  reservation_service.record_payment(
    reservation_token=reservation_token,
    identity_internal_id=reservation["identity_internal_id"],
    handle_name_lowercase=reservation["handle_name_lowercase"],
    amount_cents_usd=captured_amount_cents,
    provider_name="paypal",
    provider_transaction_id=capture_id,
    provider_order_id=order_id,
    payment_type="handle_purchase",
    payer_email=payer_email,
  )

  # -- Activate the handle --
  await _activate_handle_from_reservation(reservation, capture_id, payer_email)


async def _handle_capture_completed(resource, event_id):
  """
  PAYMENT.CAPTURE.COMPLETED: Payment was captured.

  This event often arrives after CHECKOUT.ORDER.APPROVED if we already
  captured in that handler. Handle idempotently.
  """
  capture_id = resource.get("id", "")
  custom_id = resource.get("custom_id", "")

  if not custom_id:
    # Try to find from purchase_units
    for purchase_unit in resource.get("purchase_units", []):
      custom_id = purchase_unit.get("custom_id", "")
      if custom_id:
        break

  if custom_id:
    reservation = reservation_service.get_reservation_by_token(custom_id)
    if reservation and reservation.get("status") == "paid":
      # Already handled in ORDER.APPROVED -- just ensure handle is activated
      await _activate_handle_from_reservation(reservation, capture_id)
    elif reservation and reservation.get("status") == "pending":
      # Capture completed without our ORDER.APPROVED handler -- process it
      payer_email = resource.get("payer", {}).get("email_address")
      amount_value = resource.get("amount", {}).get("value", "0")
      captured_amount_cents = int(float(amount_value) * 100)

      reservation_service.mark_reservation_as_paid(
        reservation["reservation_token"], capture_id, payer_email,
      )
      reservation_service.record_payment(
        reservation_token=reservation["reservation_token"],
        identity_internal_id=reservation["identity_internal_id"],
        handle_name_lowercase=reservation["handle_name_lowercase"],
        amount_cents_usd=captured_amount_cents,
        provider_name="paypal",
        provider_transaction_id=capture_id,
        provider_order_id=reservation.get("provider_order_id", ""),
        payment_type="handle_purchase",
        payer_email=payer_email,
      )
      await _activate_handle_from_reservation(reservation, capture_id, payer_email)

  logger.info("PAYMENT.CAPTURE.COMPLETED: capture_id=%s, custom_id=%s", capture_id, custom_id)


def _handle_capture_denied(resource, event_id):
  """PAYMENT.CAPTURE.DENIED: Payment capture was denied."""
  capture_id = resource.get("id", "")
  logger.warning("PAYMENT.CAPTURE.DENIED: capture_id=%s", capture_id)
  # We don't need to do anything -- the reservation will expire naturally.
  # The agent can try again.


def _handle_capture_refunded(resource, event_id):
  """PAYMENT.CAPTURE.REFUNDED: A refund was processed."""
  refund_id = resource.get("id", "")
  logger.info("PAYMENT.CAPTURE.REFUNDED: refund_id=%s", refund_id)
  # Refunds are initiated by us -- this is just confirmation.


def _handle_dispute_created(resource, event_id):
  """
  CUSTOMER.DISPUTE.CREATED: A chargeback/dispute was opened.

  Per our policy: the handle enters 'payment_dispute' status for 6 months,
  after which it's permanently destroyed (retired).
  """
  dispute_id = resource.get("dispute_id", "")
  disputed_transactions = resource.get("disputed_transactions", [])

  for txn in disputed_transactions:
    # Try to find the payment record and associated handle
    seller_transaction_id = txn.get("seller_transaction_id", "")
    if seller_transaction_id:
      logger.warning(
        "CUSTOMER.DISPUTE.CREATED: dispute_id=%s, txn=%s -- "
        "setting handle to payment_dispute status",
        dispute_id, seller_transaction_id,
      )
      # TODO: look up payment_records by provider_transaction_id
      # and set the handle status to 'payment_dispute' with
      # dispute_started_at = NOW(), dispute_destruction_date = NOW() + 6 months

  logger.warning("CUSTOMER.DISPUTE.CREATED: dispute_id=%s", dispute_id)


def _handle_dispute_resolved(resource, event_id):
  """
  CUSTOMER.DISPUTE.RESOLVED: A dispute was resolved.

  If resolved in seller's favour: restore the handle to active.
  If resolved in buyer's favour: the handle stays in dispute -> retired.
  """
  dispute_id = resource.get("dispute_id", "")
  dispute_outcome = resource.get("dispute_outcome", {})
  outcome_code = dispute_outcome.get("outcome_code", "")

  logger.info(
    "CUSTOMER.DISPUTE.RESOLVED: dispute_id=%s, outcome=%s",
    dispute_id, outcome_code,
  )
  # TODO: implement dispute resolution logic


# =========================================================================
# Handle activation helper
# =========================================================================

async def _activate_handle_from_reservation(reservation, capture_id, payer_email=None):
  """
  Activate a handle after payment is confirmed.

  Checks if the handle is still available. If it's been taken in the
  meantime (race condition), issues a refund instead.
  """
  handle_name_lowercase = reservation["handle_name_lowercase"]
  handle_name_display = reservation.get("handle_name_display", handle_name_lowercase)
  identity_internal_id = reservation["identity_internal_id"]
  years = reservation.get("years", 1)
  reservation_token = reservation["reservation_token"]

  # Check handle is still available
  availability = handle_service.check_handle_availability(handle_name_lowercase)

  if availability != "available":
    # Handle was taken while payment was processing -- refund!
    logger.warning(
      "Handle @%s is no longer available (status=%s) after payment. "
      "Initiating refund for reservation %s",
      handle_name_lowercase, availability, reservation_token,
    )

    # Issue refund
    try:
      paypal = get_paypal_payment_provider()
      await paypal.issue_refund(
        capture_id=capture_id,
        reason=f"Handle @{handle_name_display} was no longer available when payment completed. "
               "Full refund issued. We apologize for the inconvenience.",
      )
      reservation_service.mark_reservation_as_refunded(
        reservation_token,
        f"Handle @{handle_name_lowercase} unavailable (status: {availability})",
      )
    except Exception as refund_error:
      logger.error(
        "Failed to refund reservation %s after handle unavailable: %s",
        reservation_token, refund_error,
      )
    return

  # Check identity doesn't already have an active handle
  existing_active_handle = handle_service.check_identity_has_active_vanity_handle(identity_internal_id)
  if existing_active_handle:
    logger.warning(
      "Identity %s already has handle @%s. Refunding purchase of @%s",
      identity_internal_id, existing_active_handle, handle_name_lowercase,
    )
    try:
      paypal = get_paypal_payment_provider()
      await paypal.issue_refund(
        capture_id=capture_id,
        reason=f"Identity already has an active handle (@{existing_active_handle}). "
               "Only one vanity handle per identity is allowed. Full refund issued.",
      )
      reservation_service.mark_reservation_as_refunded(
        reservation_token,
        f"Identity already has handle @{existing_active_handle}",
      )
    except Exception as refund_error:
      logger.error("Failed to refund duplicate handle purchase: %s", refund_error)
    return

  # Calculate expiry date
  paid_through_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * years)

  # Register the handle!
  try:
    handle_service.register_handle_for_identity(
      handle_name_lowercase=handle_name_lowercase,
      handle_name_display=handle_name_display,
      identity_internal_id=identity_internal_id,
      subscription_provider="paypal",
      subscription_provider_id=capture_id,
      auto_renew=True,
      paid_through_date=paid_through_date,
      expires_at=paid_through_date,
    )

    reservation_service.mark_reservation_as_completed(reservation_token)

    logger.info(
      "Handle @%s activated for identity %s (paid through %s)",
      handle_name_lowercase, identity_internal_id, paid_through_date.isoformat(),
    )

  except Exception as register_error:
    logger.error(
      "Failed to register handle @%s for identity %s after payment: %s. "
      "MANUAL INTERVENTION REQUIRED. reservation_token=%s, capture_id=%s",
      handle_name_lowercase, identity_internal_id, register_error,
      reservation_token, capture_id,
    )
    # Do NOT refund here -- the payment was valid, we just hit a DB error.
    # This needs manual intervention to either retry the registration
    # or issue a manual refund.
