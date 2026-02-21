-- ==========================================================================
-- Migration 002: Phase 2 -- PayPal Integration
-- ==========================================================================
-- Date: 2026-02-13
-- Description: Schema adjustments for the PayPal integration layer.
--   Reworks handle_reservations and payment_records to match the actual
--   PayPal order/capture/webhook flow.
--
-- Run on: vaf (production MySQL, database: oneid)
-- Run as: sudo cat 002_phase2_paypal_integration.sql | sudo mysql oneid
--
-- IMPORTANT: This migration assumes 001_phase1_handle_payments_foundation.sql
-- has already been applied.
-- ==========================================================================


-- --------------------------------------------------------------------------
-- 1. DROP and RECREATE `handle_reservations` (no live data yet)
-- --------------------------------------------------------------------------
-- The Phase 1 schema used different column names than the payment flow
-- actually needs. Since this table has no production data yet (payments
-- haven't gone live), we can safely recreate it.

DROP TABLE IF EXISTS handle_reservations;

CREATE TABLE handle_reservations (
  reservation_token         VARCHAR(48)   NOT NULL PRIMARY KEY,   -- secrets.token_urlsafe(32)
  handle_name_lowercase     VARCHAR(63)   NOT NULL,               -- lowercase for lookup
  handle_name_display       VARCHAR(63)   NOT NULL,               -- case-preserved for display

  identity_internal_id      VARCHAR(12)   NOT NULL,               -- FK -> identities

  amount_cents_usd          INT           NOT NULL,               -- total charge in cents
  years                     INT           NOT NULL DEFAULT 1,     -- years being purchased

  payment_path              VARCHAR(20)   NOT NULL DEFAULT 'direct',
    -- 'direct' (Path A: agent pays), 'agent_relayed' (Path B), 'platform_sends' (Path C)

  provider_order_id         VARCHAR(128)  NULL,                   -- PayPal order ID
  provider_capture_id       VARCHAR(128)  NULL,                   -- PayPal capture ID (after payment)

  operator_contact_method   VARCHAR(20)   NULL,                   -- 'email', 'phone', etc.
  operator_contact_value    VARCHAR(255)  NULL,                   -- the actual contact info
  agent_message_to_operator TEXT          NULL,                   -- agent's explanation for owner

  payer_email               VARCHAR(255)  NULL,                   -- from PayPal, after payment

  status                    VARCHAR(20)   NOT NULL DEFAULT 'pending',
    -- 'pending' -> 'paid' -> 'completed'
    -- 'pending' -> 'expired'
    -- 'paid'    -> 'refunded' (handle was unavailable)

  created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at                DATETIME      NOT NULL,               -- pending reservation expiry
  paid_at                   DATETIME      NULL,                   -- when payment was confirmed

  INDEX idx_res_handle_status (handle_name_lowercase, status),
  INDEX idx_res_expiry (expires_at, status),
  INDEX idx_res_provider_order (provider_order_id),
  INDEX idx_res_identity (identity_internal_id),
  CONSTRAINT fk_res_identity FOREIGN KEY (identity_internal_id)
    REFERENCES identities(internal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- --------------------------------------------------------------------------
-- 2. DROP and RECREATE `payment_records` (no live data yet)
-- --------------------------------------------------------------------------
-- Same reasoning: reworked to match the actual payment flow.

DROP TABLE IF EXISTS payment_records;

CREATE TABLE payment_records (
  id                        INT           NOT NULL AUTO_INCREMENT PRIMARY KEY,
  reservation_token         VARCHAR(48)   NULL,                   -- FK -> handle_reservations (NULL for subscription renewals)
  identity_internal_id      VARCHAR(12)   NOT NULL,
  handle_name_lowercase     VARCHAR(63)   NULL,

  amount_cents_usd          INT           NOT NULL,
  provider_name             VARCHAR(16)   NOT NULL,               -- 'paypal'
  provider_transaction_id   VARCHAR(128)  NOT NULL,               -- capture_id or txn_id
  provider_order_id         VARCHAR(128)  NULL,                   -- PayPal order ID
  payment_type              VARCHAR(24)   NOT NULL,
    -- 'handle_purchase', 'handle_renewal', 'handle_change_fee'

  payer_email               VARCHAR(255)  NULL,

  status                    VARCHAR(16)   NOT NULL DEFAULT 'completed',
    -- 'completed', 'refunded', 'disputed', 'chargeback'

  refunded_at               DATETIME      NULL,
  disputed_at               DATETIME      NULL,
  dispute_resolved_at       DATETIME      NULL,
  dispute_outcome           VARCHAR(16)   NULL,                   -- 'seller_won', 'buyer_won'

  created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  INDEX idx_pay_identity (identity_internal_id),
  INDEX idx_pay_handle (handle_name_lowercase),
  INDEX idx_pay_provider_txn (provider_transaction_id),
  INDEX idx_pay_reservation (reservation_token),
  CONSTRAINT fk_pay_identity FOREIGN KEY (identity_internal_id)
    REFERENCES identities(internal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- --------------------------------------------------------------------------
-- Done!
-- --------------------------------------------------------------------------
SELECT 'Migration 002 complete: Phase 2 PayPal Integration' AS result;
