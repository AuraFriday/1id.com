-- ==========================================================================
-- Migration 001: Phase 1 -- Handle Payments Foundation
-- ==========================================================================
-- Date: 2026-02-13
-- Description: Schema changes for handle sales, payments, operator emails,
--   reserved handles, and case-preserving display.
--
-- Run on: vaf (production MySQL, database: oneid)
-- Run as: mysql -u oneid -p oneid < 001_phase1_handle_payments_foundation.sql
--
-- IMPORTANT: This migration is IDEMPOTENT (safe to re-run) where possible.
--   New tables use IF NOT EXISTS.
--   ALTER TABLE statements may fail on re-run if columns already exist --
--   that's expected and safe.
-- ==========================================================================

-- --------------------------------------------------------------------------
-- 1. ALTER TABLE `handles` -- add new columns for payments and case display
-- --------------------------------------------------------------------------

-- Case-preserving display: stores the casing the owner entered (e.g. 'ChrisDrake')
-- handle_name (PK) is always lowercase ('chrisdrake') for lookups.
ALTER TABLE handles
  ADD COLUMN handle_name_display VARCHAR(63) NOT NULL DEFAULT '' AFTER handle_name;

-- Backfill: set display form = lowercase form for existing handles
UPDATE handles SET handle_name_display = handle_name WHERE handle_name_display = '';

-- Subscription and expiry tracking columns
ALTER TABLE handles
  ADD COLUMN subscription_provider VARCHAR(16) NULL AFTER pricing_tier,
  ADD COLUMN subscription_provider_id VARCHAR(128) NULL AFTER subscription_provider,
  ADD COLUMN auto_renew TINYINT(1) NOT NULL DEFAULT 1 AFTER subscription_provider_id,
  ADD COLUMN paid_through_date DATETIME NULL AFTER expires_at,
  ADD COLUMN dispute_started_at DATETIME NULL AFTER retired_at,
  ADD COLUMN dispute_destruction_date DATETIME NULL AFTER dispute_started_at;

-- Expand status field to accommodate new statuses
-- Values: 'active', 'expired', 'payment_dispute', 'retired'
-- Removed: 'dormant' (replaced by 'expired' with immediate effect)
ALTER TABLE handles
  MODIFY COLUMN status VARCHAR(20) NOT NULL;

-- Expand handle_name to 63 chars (DNS label max) from 64
-- (Technically 63 is the DNS max, but 64 already fits, so this is a no-op
-- unless the column was exactly 63. Keep for documentation.)
ALTER TABLE handles
  MODIFY COLUMN handle_name VARCHAR(63) NOT NULL;

-- Migrate existing 'dormant' handles to 'expired'
UPDATE handles SET status = 'expired' WHERE status = 'dormant';


-- --------------------------------------------------------------------------
-- 2. CREATE TABLE `reserved_handles`
-- --------------------------------------------------------------------------
-- Holds handles that cannot be registered by the public:
--   - Operator's personal reserved list (brands, names, friends)
--   - Legacy I-Names honour program names
--   - System-reserved names (loaded via admin tooling)

CREATE TABLE IF NOT EXISTS reserved_handles (
  handle_name_lowercase     VARCHAR(63)   NOT NULL PRIMARY KEY,
  reserved_by               VARCHAR(128)  NOT NULL,               -- who: 'operator', 'system', 'rfc2142', 'legacy_inames'
  reason                    VARCHAR(255)  NULL,                   -- why reserved
  reserved_for_identity     VARCHAR(12)   NULL,                   -- optional: pre-assigned to a specific identity
  coupon_code               VARCHAR(64)   NULL,                   -- unique coupon (legacy I-Names honour program)
  coupon_issued_at          DATETIME      NULL,
  coupon_expires_at         DATETIME      NULL,                   -- 6 months after issuance
  coupon_redeemed_at        DATETIME      NULL,
  coupon_redeemed_by        VARCHAR(12)   NULL,                   -- identity that redeemed
  claimant_email            VARCHAR(255)  NULL,                   -- legacy customer email
  claim_deadline            DATETIME      NULL,                   -- 2 weeks after outreach email
  legacy_original_name      VARCHAR(255)  NULL,                   -- original I-Names name (may differ)
  created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uk_coupon_code (coupon_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- --------------------------------------------------------------------------
-- 3. CREATE TABLE `handle_reservations`
-- --------------------------------------------------------------------------
-- Temporary 30-minute reservations during payment processing.

CREATE TABLE IF NOT EXISTS handle_reservations (
  reservation_id            VARCHAR(16)   NOT NULL PRIMARY KEY,   -- e.g. 'hr_a8b3c7d9'
  handle_name               VARCHAR(63)   NOT NULL,               -- lowercase
  handle_name_display       VARCHAR(63)   NOT NULL,               -- case-preserved
  identity_internal_id      VARCHAR(12)   NOT NULL,
  payment_provider          VARCHAR(16)   NOT NULL DEFAULT 'paypal',
  payment_provider_order_id VARCHAR(128)  NULL,                   -- PayPal order/invoice ID
  payment_provider_subscription_id VARCHAR(128) NULL,
  payment_status            VARCHAR(20)   NOT NULL DEFAULT 'pending',
    -- 'pending', 'paid', 'activated', 'expired', 'refunded', 'cancelled'
  annual_fee_cents_usd      INT           NOT NULL,
  total_charge_cents_usd    INT           NOT NULL,
  years_purchased           INT           NOT NULL DEFAULT 1,
  auto_renew                TINYINT(1)    NOT NULL DEFAULT 1,
  reservation_type          VARCHAR(16)   NOT NULL DEFAULT 'new_registration',
    -- 'new_registration', 'renewal', 'handle_change'
  operator_email_for_invoice VARCHAR(255) NULL,
  agent_display_name_for_invoice VARCHAR(128) NULL,
  agent_message_to_operator TEXT          NULL,
  created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at                DATETIME      NOT NULL,
  paid_at                   DATETIME      NULL,
  activated_at              DATETIME      NULL,

  INDEX idx_reservation_handle_status (handle_name, payment_status),
  INDEX idx_reservation_expiry (expires_at, payment_status),
  CONSTRAINT fk_reservation_identity FOREIGN KEY (identity_internal_id)
    REFERENCES identities(internal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- --------------------------------------------------------------------------
-- 4. CREATE TABLE `payment_records`
-- --------------------------------------------------------------------------
-- Permanent record of all payments. 7-year retention per US tax law.

CREATE TABLE IF NOT EXISTS payment_records (
  payment_id                VARCHAR(16)   NOT NULL PRIMARY KEY,   -- e.g. 'pay_x9m2q4k7'
  reservation_id            VARCHAR(16)   NULL,                   -- FK → handle_reservations (NULL for subscription renewals)
  identity_internal_id      VARCHAR(12)   NOT NULL,
  handle_name               VARCHAR(63)   NULL,
  payment_provider          VARCHAR(16)   NOT NULL,               -- 'paypal'
  payment_provider_txn_id   VARCHAR(128)  NOT NULL,
  payment_provider_subscription_id VARCHAR(128) NULL,
  amount_cents_usd          INT           NOT NULL,
  payment_type              VARCHAR(24)   NOT NULL,
    -- 'handle_new_registration', 'handle_renewal', 'handle_change_abandonment_fee',
    -- 'handle_change_new_registration', 'handle_lapsed_renewal'
  status                    VARCHAR(16)   NOT NULL,
    -- 'completed', 'refunded', 'disputed', 'chargeback'
  paid_at                   DATETIME      NOT NULL,
  refunded_at               DATETIME      NULL,
  disputed_at               DATETIME      NULL,
  dispute_resolved_at       DATETIME      NULL,
  dispute_outcome           VARCHAR(16)   NULL,                   -- 'seller_won', 'buyer_won'
  payer_email               VARCHAR(255)  NULL,                   -- from PayPal, for records
  created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  INDEX idx_payment_identity (identity_internal_id),
  INDEX idx_payment_handle (handle_name),
  INDEX idx_payment_provider_txn (payment_provider_txn_id),
  CONSTRAINT fk_payment_identity FOREIGN KEY (identity_internal_id)
    REFERENCES identities(internal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- --------------------------------------------------------------------------
-- 5. CREATE TABLE `operator_emails`
-- --------------------------------------------------------------------------
-- Multiple operator emails per identity, with independent verification.

CREATE TABLE IF NOT EXISTS operator_emails (
  id                        INT           NOT NULL AUTO_INCREMENT PRIMARY KEY,
  identity_internal_id      VARCHAR(12)   NOT NULL,
  email_address             VARCHAR(255)  NOT NULL,
  is_primary                TINYINT(1)    NOT NULL DEFAULT 0,
  is_verified               TINYINT(1)    NOT NULL DEFAULT 0,
  verification_token        VARCHAR(64)   NULL,
  verification_sent_at      DATETIME      NULL,
  verification_completed_at DATETIME      NULL,
  is_unsubscribed           TINYINT(1)    NOT NULL DEFAULT 0,
  added_at                  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_email_sent_at        DATETIME      NULL,

  UNIQUE KEY uk_identity_email (identity_internal_id, email_address),
  INDEX idx_opmail_identity (identity_internal_id),
  CONSTRAINT fk_opmail_identity FOREIGN KEY (identity_internal_id)
    REFERENCES identities(internal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- --------------------------------------------------------------------------
-- 6. Migrate existing operator_email data from identities to operator_emails
-- --------------------------------------------------------------------------
-- Copy non-null operator_email values into the new table as primary emails.
-- This is safe to re-run (INSERT IGNORE skips duplicates).

INSERT IGNORE INTO operator_emails
  (identity_internal_id, email_address, is_primary, is_verified)
SELECT
  internal_id,
  operator_email,
  1,
  operator_email_verified
FROM identities
WHERE operator_email IS NOT NULL AND operator_email != '';


-- --------------------------------------------------------------------------
-- 7. ALTER TABLE `identities` -- future-proofing columns
-- --------------------------------------------------------------------------

ALTER TABLE identities
  ADD COLUMN operator_is_human_confirmed TINYINT(1) NOT NULL DEFAULT 0 AFTER operator_email_verified,
  ADD COLUMN operator_approved_agent TINYINT(1) NOT NULL DEFAULT 0 AFTER operator_is_human_confirmed;

-- Note: operator_email and operator_email_verified columns are KEPT for now
-- (backward compatibility). Code should read from operator_emails table.
-- These columns will be dropped in a future migration.


-- --------------------------------------------------------------------------
-- Done!
-- --------------------------------------------------------------------------
SELECT 'Migration 001 complete: Phase 1 Handle Payments Foundation' AS result;
