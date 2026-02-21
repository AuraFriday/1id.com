"""
1id.com -- Payment Provider Interface

Abstract base class for payment providers (PayPal, Stripe, etc.).
Each provider implements this interface. The handle purchase/renewal
logic is provider-agnostic -- it only talks to this interface.
"""

from abc import ABC, abstractmethod


class PaymentProviderInterface(ABC):
  """Abstract base for payment providers."""

  @abstractmethod
  async def create_checkout_order(
    self,
    amount_cents_usd,
    description,
    custom_id,
    return_url,
    cancel_url,
  ):
    """
    Create a one-time payment order for buyer-approved checkout.

    Args:
      amount_cents_usd: Amount in USD cents (integer).
      description: Human-readable description of what's being purchased.
      custom_id: Our internal reference (e.g., reservation_id).
      return_url: URL the buyer is redirected to after approval.
      cancel_url: URL the buyer is redirected to if they cancel.

    Returns: dict with at minimum:
      {
        "provider_order_id": "...",   # provider's order ID
        "approval_url": "...",        # URL for buyer to approve payment
      }
    """
    ...

  @abstractmethod
  async def capture_order(self, provider_order_id):
    """
    Capture (finalize) a previously approved order.

    Args:
      provider_order_id: The provider's order ID from create_checkout_order.

    Returns: dict with at minimum:
      {
        "capture_id": "...",          # provider's capture/transaction ID
        "status": "COMPLETED",        # payment status
        "amount_cents_usd": 1000,     # captured amount in cents
        "payer_email": "...",         # payer's email (if available)
      }
    """
    ...

  @abstractmethod
  async def issue_refund(self, capture_id, amount_cents_usd, reason):
    """
    Refund a previously captured payment (full or partial).

    Args:
      capture_id: The provider's capture ID from capture_order.
      amount_cents_usd: Amount to refund in cents. None = full refund.
      reason: Human-readable reason for the refund.

    Returns: dict with at minimum:
      {
        "refund_id": "...",           # provider's refund ID
        "status": "COMPLETED",        # refund status
      }
    """
    ...

  @abstractmethod
  async def verify_webhook_signature(self, headers, raw_body):
    """
    Verify that a webhook payload was genuinely sent by this provider.

    Args:
      headers: HTTP headers from the webhook request (dict).
      raw_body: Raw request body bytes.

    Returns: True if signature is valid, False otherwise.
    """
    ...
