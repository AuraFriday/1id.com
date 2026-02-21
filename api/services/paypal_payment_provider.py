"""
1id.com -- PayPal Payment Provider

PayPal REST API v2 integration using direct HTTP calls via httpx.
No heavy SDK dependency -- just the same httpx we already use for Keycloak.

Live mode from day one (no sandbox).

Endpoints used:
  POST /v1/oauth2/token              -- get bearer token
  POST /v2/checkout/orders           -- create order
  POST /v2/checkout/orders/{id}/capture -- capture payment
  POST /v2/payments/captures/{id}/refund -- refund
  POST /v1/notifications/verify-webhook-signature -- verify webhook
"""

import hashlib
import json
import logging
import time

import httpx

import config
from services.payment_provider_interface import PaymentProviderInterface

logger = logging.getLogger("oneid.paypal")

# ---------------------------------------------------------------------------
# OAuth2 token cache (module-level, thread-safe for single-process uvicorn)
# ---------------------------------------------------------------------------
_cached_paypal_oauth_token = None
_cached_paypal_oauth_token_expires_at = 0


class PayPalPaymentProvider(PaymentProviderInterface):
  """PayPal REST API v2 payment provider."""

  def __init__(self):
    self.api_base_url = config.PAYPAL_API_BASE_URL
    self.client_id = config.PAYPAL_CLIENT_ID
    self.secret_key = config.PAYPAL_SECRET_KEY
    self.webhook_id = config.PAYPAL_WEBHOOK_ID

  # -----------------------------------------------------------------------
  # OAuth2 bearer token
  # -----------------------------------------------------------------------

  async def _get_access_token(self):
    """
    Get a PayPal OAuth2 bearer token. Caches until near expiry.
    Uses client_credentials grant with HTTP Basic auth.
    """
    global _cached_paypal_oauth_token, _cached_paypal_oauth_token_expires_at

    now = time.time()
    if _cached_paypal_oauth_token and now < _cached_paypal_oauth_token_expires_at - 60:
      return _cached_paypal_oauth_token

    async with httpx.AsyncClient() as http_client:
      response = await http_client.post(
        f"{self.api_base_url}/v1/oauth2/token",
        auth=(self.client_id, self.secret_key),
        data={"grant_type": "client_credentials"},
        headers={"Accept": "application/json"},
      )
      response.raise_for_status()
      token_data = response.json()

    _cached_paypal_oauth_token = token_data["access_token"]
    _cached_paypal_oauth_token_expires_at = now + token_data.get("expires_in", 3600)

    logger.info("PayPal OAuth2 token refreshed (expires_in=%s)", token_data.get("expires_in"))
    return _cached_paypal_oauth_token

  async def _auth_headers(self):
    """Get Authorization headers for PayPal API calls."""
    token = await self._get_access_token()
    return {
      "Authorization": f"Bearer {token}",
      "Content-Type": "application/json",
    }

  # -----------------------------------------------------------------------
  # Create checkout order
  # -----------------------------------------------------------------------

  async def create_checkout_order(
    self,
    amount_cents_usd,
    description,
    custom_id,
    return_url,
    cancel_url,
  ):
    """
    Create a PayPal order for buyer-approved checkout.

    The buyer must visit the approval_url to approve the payment.
    After approval, PayPal sends a webhook and we capture the payment.
    """
    amount_usd = f"{amount_cents_usd / 100:.2f}"

    order_payload = {
      "intent": "CAPTURE",
      "purchase_units": [{
        "reference_id": custom_id,
        "description": description[:127],  # PayPal max 127 chars
        "custom_id": custom_id,
        "amount": {
          "currency_code": "USD",
          "value": amount_usd,
        },
      }],
      "payment_source": {
        "paypal": {
          "experience_context": {
            "payment_method_preference": "IMMEDIATE_PAYMENT_REQUIRED",
            "brand_name": "1id.com",
            "locale": "en-US",
            "landing_page": "LOGIN",
            "user_action": "PAY_NOW",
            "return_url": return_url,
            "cancel_url": cancel_url,
          }
        }
      },
    }

    headers = await self._auth_headers()
    headers["PayPal-Request-Id"] = custom_id  # idempotency key

    async with httpx.AsyncClient() as http_client:
      response = await http_client.post(
        f"{self.api_base_url}/v2/checkout/orders",
        json=order_payload,
        headers=headers,
      )
      response.raise_for_status()
      order_data = response.json()

    # Find the approval URL from HATEOAS links
    approval_url = None
    for link in order_data.get("links", []):
      if link.get("rel") == "payer-action":
        approval_url = link["href"]
        break
    if not approval_url:
      for link in order_data.get("links", []):
        if link.get("rel") == "approve":
          approval_url = link["href"]
          break

    provider_order_id = order_data["id"]

    logger.info(
      "PayPal order created: order_id=%s, amount=$%s, custom_id=%s",
      provider_order_id, amount_usd, custom_id,
    )

    return {
      "provider_order_id": provider_order_id,
      "approval_url": approval_url,
      "status": order_data.get("status", "CREATED"),
    }

  # -----------------------------------------------------------------------
  # Capture order
  # -----------------------------------------------------------------------

  async def capture_order(self, provider_order_id):
    """
    Capture (finalize) a previously approved PayPal order.

    Called after the buyer approves payment (via webhook or polling).
    """
    headers = await self._auth_headers()
    headers["Prefer"] = "return=representation"

    async with httpx.AsyncClient() as http_client:
      response = await http_client.post(
        f"{self.api_base_url}/v2/checkout/orders/{provider_order_id}/capture",
        headers=headers,
        json={},  # empty body for simple capture
      )
      response.raise_for_status()
      capture_data = response.json()

    # Extract capture details from purchase units
    capture_id = None
    captured_amount_cents = 0
    payer_email = None

    payer_info = capture_data.get("payer", {})
    payer_email = payer_info.get("email_address")

    for purchase_unit in capture_data.get("purchase_units", []):
      payments = purchase_unit.get("payments", {})
      for capture in payments.get("captures", []):
        capture_id = capture.get("id")
        amount_value = capture.get("amount", {}).get("value", "0")
        captured_amount_cents = int(float(amount_value) * 100)

    logger.info(
      "PayPal payment captured: order_id=%s, capture_id=%s, amount_cents=%s",
      provider_order_id, capture_id, captured_amount_cents,
    )

    return {
      "capture_id": capture_id,
      "status": capture_data.get("status", "UNKNOWN"),
      "amount_cents_usd": captured_amount_cents,
      "payer_email": payer_email,
    }

  # -----------------------------------------------------------------------
  # Issue refund
  # -----------------------------------------------------------------------

  async def issue_refund(self, capture_id, amount_cents_usd=None, reason=None):
    """
    Refund a previously captured payment.
    If amount_cents_usd is None, issues a full refund.
    """
    headers = await self._auth_headers()

    refund_payload = {}
    if amount_cents_usd is not None:
      refund_payload["amount"] = {
        "currency_code": "USD",
        "value": f"{amount_cents_usd / 100:.2f}",
      }
    if reason:
      refund_payload["note_to_payer"] = reason[:255]  # PayPal max

    async with httpx.AsyncClient() as http_client:
      response = await http_client.post(
        f"{self.api_base_url}/v2/payments/captures/{capture_id}/refund",
        json=refund_payload,
        headers=headers,
      )
      response.raise_for_status()
      refund_data = response.json()

    logger.info(
      "PayPal refund issued: capture_id=%s, refund_id=%s, status=%s",
      capture_id, refund_data.get("id"), refund_data.get("status"),
    )

    return {
      "refund_id": refund_data.get("id"),
      "status": refund_data.get("status", "UNKNOWN"),
    }

  # -----------------------------------------------------------------------
  # Verify webhook signature
  # -----------------------------------------------------------------------

  async def verify_webhook_signature(self, headers, raw_body):
    """
    Verify a PayPal webhook signature using PayPal's verification API.

    PayPal provides a server-side verification endpoint that checks
    the transmission signature. This is the recommended approach.
    """
    # Extract PayPal transmission headers (case-insensitive)
    header_map = {k.lower(): v for k, v in headers.items()}

    transmission_id = header_map.get("paypal-transmission-id", "")
    transmission_time = header_map.get("paypal-transmission-time", "")
    transmission_sig = header_map.get("paypal-transmission-sig", "")
    cert_url = header_map.get("paypal-cert-url", "")
    auth_algo = header_map.get("paypal-auth-algo", "SHA256withRSA")

    if not all([transmission_id, transmission_time, transmission_sig, cert_url]):
      logger.warning("PayPal webhook missing required transmission headers")
      return False

    # Use PayPal's verification API
    verification_payload = {
      "auth_algo": auth_algo,
      "cert_url": cert_url,
      "transmission_id": transmission_id,
      "transmission_sig": transmission_sig,
      "transmission_time": transmission_time,
      "webhook_id": self.webhook_id,
      "webhook_event": json.loads(raw_body) if isinstance(raw_body, (bytes, str)) else raw_body,
    }

    auth_headers = await self._auth_headers()

    try:
      async with httpx.AsyncClient() as http_client:
        response = await http_client.post(
          f"{self.api_base_url}/v1/notifications/verify-webhook-signature",
          json=verification_payload,
          headers=auth_headers,
        )
        response.raise_for_status()
        result = response.json()

      verification_status = result.get("verification_status", "")
      is_valid = verification_status == "SUCCESS"

      if not is_valid:
        logger.warning(
          "PayPal webhook signature verification failed: status=%s, transmission_id=%s",
          verification_status, transmission_id,
        )

      return is_valid

    except Exception as verification_error:
      logger.error(
        "PayPal webhook signature verification error: %s", verification_error
      )
      return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_paypal_provider_singleton = None


def get_paypal_payment_provider():
  """Get the PayPal payment provider singleton."""
  global _paypal_provider_singleton
  if _paypal_provider_singleton is None:
    _paypal_provider_singleton = PayPalPaymentProvider()
  return _paypal_provider_singleton
