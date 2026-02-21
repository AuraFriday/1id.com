"""
1id.com -- Handle Reservation Service

Manages the 30-minute reservation lifecycle for handle purchases.

Reservation flow:
  1. Agent requests a handle -> we create a reservation (30 min TTL)
  2. Agent or operator completes payment within 30 minutes
  3. Webhook confirms payment -> we activate the handle
  4. If payment arrives late but handle is still free -> allow it
  5. If payment arrives late and handle is taken -> refund

Reservations are stored in the `handle_reservations` table.
"""

import datetime
import logging
import secrets

import config

logger = logging.getLogger("oneid.reservations")


def _get_database():
  """Lazy import to allow unit testing without live DB."""
  import database
  return database


def create_handle_reservation(
  handle_name_lowercase,
  handle_name_display,
  identity_internal_id,
  amount_cents_usd,
  years,
  payment_path,
  provider_order_id=None,
  operator_contact_method=None,
  operator_contact_value=None,
  agent_message_to_operator=None,
):
  """
  Create a 30-minute reservation for a handle purchase.

  Args:
    handle_name_lowercase: The handle being reserved (lowercase).
    handle_name_display: The display form of the handle.
    identity_internal_id: The identity requesting the handle.
    amount_cents_usd: Total price in USD cents.
    years: Number of years being purchased.
    payment_path: 'direct' | 'agent_relayed' | 'platform_sends'.
    provider_order_id: PayPal order ID (if already created).
    operator_contact_method: 'email' | 'phone' | 'other' (for path C).
    operator_contact_value: The actual contact info (for path C).
    agent_message_to_operator: The agent's explanation for the operator.

  Returns: dict with reservation details.
  """
  db = _get_database()

  reservation_token = secrets.token_urlsafe(32)
  expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
    seconds=config.HANDLE_RESERVATION_TTL_SECONDS
  )

  db.execute_insert_or_update(
    """
    INSERT INTO handle_reservations
      (reservation_token, handle_name_lowercase, handle_name_display,
       identity_internal_id, amount_cents_usd, years,
       payment_path, provider_order_id,
       operator_contact_method, operator_contact_value,
       agent_message_to_operator,
       status, expires_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)
    """,
    (
      reservation_token,
      handle_name_lowercase,
      handle_name_display,
      identity_internal_id,
      amount_cents_usd,
      years,
      payment_path,
      provider_order_id,
      operator_contact_method,
      operator_contact_value,
      agent_message_to_operator,
      expires_at,
    ),
  )

  logger.info(
    "Handle reservation created: handle=%s, identity=%s, path=%s, amount=%d cents, expires=%s",
    handle_name_lowercase, identity_internal_id, payment_path,
    amount_cents_usd, expires_at.isoformat(),
  )

  return {
    "reservation_token": reservation_token,
    "handle_name_lowercase": handle_name_lowercase,
    "handle_name_display": handle_name_display,
    "identity_internal_id": identity_internal_id,
    "amount_cents_usd": amount_cents_usd,
    "years": years,
    "payment_path": payment_path,
    "status": "pending",
    "expires_at": expires_at.isoformat(),
  }


def get_reservation_by_token(reservation_token):
  """
  Look up a reservation by its unique token.
  Returns the row as a dict, or None.
  """
  db = _get_database()
  return db.execute_query_returning_one_row(
    "SELECT * FROM handle_reservations WHERE reservation_token = %s",
    (reservation_token,),
  )


def get_reservation_by_provider_order_id(provider_order_id):
  """
  Look up a reservation by its PayPal order ID.
  Used by the webhook to match a payment to a reservation.
  Returns the row as a dict, or None.
  """
  db = _get_database()
  return db.execute_query_returning_one_row(
    "SELECT * FROM handle_reservations WHERE provider_order_id = %s",
    (provider_order_id,),
  )


def get_pending_reservation_for_handle(handle_name_lowercase):
  """
  Check if there's an active (non-expired) pending reservation for a handle.
  Returns the row as a dict, or None.
  """
  db = _get_database()
  return db.execute_query_returning_one_row(
    """
    SELECT * FROM handle_reservations
    WHERE handle_name_lowercase = %s
      AND status = 'pending'
      AND expires_at > NOW()
    ORDER BY created_at DESC
    LIMIT 1
    """,
    (handle_name_lowercase,),
  )


def update_reservation_provider_order_id(reservation_token, provider_order_id):
  """Update a reservation with the PayPal order ID after order creation."""
  db = _get_database()
  db.execute_insert_or_update(
    """
    UPDATE handle_reservations
    SET provider_order_id = %s
    WHERE reservation_token = %s
    """,
    (provider_order_id, reservation_token),
  )


def mark_reservation_as_paid(reservation_token, capture_id, payer_email=None):
  """Mark a reservation as paid (payment confirmed)."""
  db = _get_database()
  db.execute_insert_or_update(
    """
    UPDATE handle_reservations
    SET status = 'paid',
        provider_capture_id = %s,
        payer_email = %s,
        paid_at = NOW()
    WHERE reservation_token = %s
    """,
    (capture_id, payer_email, reservation_token),
  )
  logger.info("Reservation marked as paid: token=%s, capture_id=%s", reservation_token, capture_id)


def mark_reservation_as_completed(reservation_token):
  """Mark a reservation as completed (handle activated)."""
  db = _get_database()
  db.execute_insert_or_update(
    """
    UPDATE handle_reservations
    SET status = 'completed'
    WHERE reservation_token = %s
    """,
    (reservation_token,),
  )
  logger.info("Reservation completed: token=%s", reservation_token)


def mark_reservation_as_refunded(reservation_token, refund_reason):
  """Mark a reservation as refunded (payment returned)."""
  db = _get_database()
  db.execute_insert_or_update(
    """
    UPDATE handle_reservations
    SET status = 'refunded'
    WHERE reservation_token = %s
    """,
    (reservation_token,),
  )
  logger.info("Reservation refunded: token=%s, reason=%s", reservation_token, refund_reason)


def mark_reservation_as_expired(reservation_token):
  """Mark a reservation as expired (30 min TTL exceeded without payment)."""
  db = _get_database()
  db.execute_insert_or_update(
    """
    UPDATE handle_reservations
    SET status = 'expired'
    WHERE reservation_token = %s
    """,
    (reservation_token,),
  )


def record_payment(
  reservation_token,
  identity_internal_id,
  handle_name_lowercase,
  amount_cents_usd,
  provider_name,
  provider_transaction_id,
  provider_order_id,
  payment_type,
  payer_email=None,
):
  """
  Record a payment in the permanent audit trail (payment_records table).

  This is the immutable financial record. Separate from reservations
  which are transient workflow state.
  """
  db = _get_database()
  db.execute_insert_or_update(
    """
    INSERT INTO payment_records
      (reservation_token, identity_internal_id, handle_name_lowercase,
       amount_cents_usd, provider_name, provider_transaction_id,
       provider_order_id, payment_type, payer_email)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """,
    (
      reservation_token,
      identity_internal_id,
      handle_name_lowercase,
      amount_cents_usd,
      provider_name,
      provider_transaction_id,
      provider_order_id,
      payment_type,
      payer_email,
    ),
  )
  logger.info(
    "Payment recorded: handle=%s, identity=%s, amount=%d cents, type=%s, txn=%s",
    handle_name_lowercase, identity_internal_id, amount_cents_usd,
    payment_type, provider_transaction_id,
  )


def expire_all_overdue_reservations():
  """
  Batch job: expire all reservations whose TTL has passed.
  Called by a cron/background task.

  Returns the number of expired reservations.
  """
  db = _get_database()
  # Get count first for logging
  rows = db.execute_query_returning_all_rows(
    """
    SELECT reservation_token FROM handle_reservations
    WHERE status = 'pending' AND expires_at <= NOW()
    """,
  )
  count = len(rows)
  if count > 0:
    db.execute_insert_or_update(
      """
      UPDATE handle_reservations
      SET status = 'expired'
      WHERE status = 'pending' AND expires_at <= NOW()
      """,
    )
    logger.info("Expired %d overdue handle reservations", count)
  return count
