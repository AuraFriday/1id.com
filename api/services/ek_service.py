"""
1id.com -- EK Certificate Service

Validates EK certificates, verifies chain against manufacturer CA trust store,
classifies trust tiers, and manages the anti-Sybil EK registry.

Trust tier classification:
  - sovereign:  EK chains to known manufacturer CA with valid (non-expired) cert
  - legacy:     EK chains to known manufacturer CA but cert is expired
  - virtual:    EK cert from a known hypervisor vendor (VMware, Hyper-V, etc.)
  - declared:   No EK (software-only enrollment -- handled separately)
"""

import hashlib
import base64
import logging
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
import database

logger = logging.getLogger("oneid.ek")

# Manufacturer codes for trust tier classification
_HYPERVISOR_MANUFACTURER_CODES = {"VMW", "MSFT_VTPM", "QEMU"}
_HARDWARE_MANUFACTURER_CODES = {"INTC", "AMD", "IFX", "NTC", "STM", "ATML"}


def compute_ek_fingerprint_sha256(ek_certificate_pem):
  """
  Compute SHA-256 fingerprint of the EK public key (not the cert).
  This is the anti-Sybil key -- same physical TPM always produces the same fingerprint.
  Returns: 64-char lowercase hex string.
  """
  cert = x509.load_pem_x509_certificate(ek_certificate_pem.encode("utf-8"))
  public_key_der = cert.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
  )
  return hashlib.sha256(public_key_der).hexdigest()


def extract_manufacturer_code_from_ek_certificate(ek_certificate_pem):
  """
  Extract manufacturer code from the EK certificate's issuer CN.
  Returns a short code like 'INTC', 'AMD', 'IFX', etc.
  """
  cert = x509.load_pem_x509_certificate(ek_certificate_pem.encode("utf-8"))

  try:
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
  except (IndexError, ValueError):
    issuer_cn = ""

  issuer_cn_upper = issuer_cn.upper()

  # Map known issuer patterns to manufacturer codes
  if "INTEL" in issuer_cn_upper or "CSME" in issuer_cn_upper:
    return "INTC"
  if "AMD" in issuer_cn_upper or "FTPM" in issuer_cn_upper:
    return "AMD"
  if "INFINEON" in issuer_cn_upper or "IFX" in issuer_cn_upper:
    return "IFX"
  if "NUVOTON" in issuer_cn_upper or "NTC" in issuer_cn_upper:
    return "NTC"
  if "STMICRO" in issuer_cn_upper or "STM" in issuer_cn_upper:
    return "STM"
  if "VMWARE" in issuer_cn_upper or "VMW" in issuer_cn_upper:
    return "VMW"
  if "MICROSOFT" in issuer_cn_upper and "VIRTUAL" in issuer_cn_upper:
    return "MSFT_VTPM"
  if "QEMU" in issuer_cn_upper:
    return "QEMU"

  try:
    issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
  except (IndexError, ValueError):
    issuer_org = ""

  issuer_org_upper = issuer_org.upper()
  if "INTEL" in issuer_org_upper:
    return "INTC"
  if "AMD" in issuer_org_upper:
    return "AMD"
  if "INFINEON" in issuer_org_upper:
    return "IFX"

  logger.warning("Unknown EK certificate issuer: CN=%s, O=%s", issuer_cn, issuer_org)
  return "UNKN"


def classify_trust_tier(manufacturer_code, ek_certificate_pem):
  """
  Classify the trust tier based on manufacturer and cert validity.

  Rules:
    - Hypervisor vendor -> 'virtual'
    - Hardware vendor + valid cert -> 'sovereign'
    - Hardware vendor + expired cert -> 'legacy'
    - Unknown vendor -> reject (raise ValueError)
  """
  if manufacturer_code in _HYPERVISOR_MANUFACTURER_CODES:
    return "virtual"

  if manufacturer_code in _HARDWARE_MANUFACTURER_CODES:
    cert = x509.load_pem_x509_certificate(ek_certificate_pem.encode("utf-8"))
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now:
      return "legacy"
    return "sovereign"

  raise ValueError(
    f"Unknown TPM manufacturer code '{manufacturer_code}' -- "
    "cannot classify trust tier. EK certificate issuer is not recognized."
  )


def check_ek_fingerprint_already_registered(ek_fingerprint_sha256):
  """
  Check if this EK fingerprint is already in the registry (Sybil check).
  Returns the existing identity_internal_id if found, or None.
  """
  row = database.execute_query_returning_one_row(
    "SELECT identity_internal_id FROM ek_registry WHERE ek_fingerprint_sha256 = %s",
    (ek_fingerprint_sha256,)
  )
  if row:
    return row["identity_internal_id"]
  return None


def register_ek_binding(
  ek_fingerprint_sha256,
  identity_internal_id,
  ek_certificate_pem,
  tpm_manufacturer_code,
  trust_tier,
):
  """Register a new EK binding in the anti-Sybil registry."""
  database.execute_insert_or_update(
    """
    INSERT INTO ek_registry
      (ek_fingerprint_sha256, identity_internal_id, ek_certificate_pem,
       tpm_manufacturer_code, trust_tier)
    VALUES (%s, %s, %s, %s, %s)
    """,
    (
      ek_fingerprint_sha256,
      identity_internal_id,
      ek_certificate_pem,
      tpm_manufacturer_code,
      trust_tier,
    )
  )


def validate_ek_certificate_chain(ek_certificate_pem, chain_pem_list=None):
  """
  Validate the EK certificate chain against the manufacturer CA trust store.

  Strategy (per 030_technical_architecture.md Section 3.2.1):
    1. Try client-provided intermediates first
    2. Fall back to server-side trust store (manufacturer_ca_certificates table)
    3. Try AIA (Authority Information Access) fetch for missing intermediates
    4. Cache newly discovered intermediates

  Returns: (is_valid, trust_tier, manufacturer_code, error_message)
  """
  try:
    cert = x509.load_pem_x509_certificate(ek_certificate_pem.encode("utf-8"))
  except Exception as parse_error:
    return False, None, None, f"Failed to parse EK certificate: {parse_error}"

  manufacturer_code = extract_manufacturer_code_from_ek_certificate(ek_certificate_pem)

  # For now: accept all parseable EK certs and classify by manufacturer.
  # Full chain validation against the CA trust store will be implemented
  # when we import the TrustedTPM.cab certificates into manufacturer_ca_certificates.
  #
  # TODO: Implement full chain validation:
  #   1. Build chain: leaf -> intermediates -> root
  #   2. Verify each signature in the chain
  #   3. Check revocation (CRL/OCSP if available)
  #   4. Match root to manufacturer_ca_certificates table

  try:
    trust_tier = classify_trust_tier(manufacturer_code, ek_certificate_pem)
  except ValueError as tier_error:
    return False, None, manufacturer_code, str(tier_error)

  logger.info(
    "EK cert validated: manufacturer=%s, tier=%s, fingerprint_prefix=%s",
    manufacturer_code,
    trust_tier,
    compute_ek_fingerprint_sha256(ek_certificate_pem)[:8],
  )

  return True, trust_tier, manufacturer_code, None
