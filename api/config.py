"""
1id.com Enrollment API -- Configuration

All configuration values with sensible defaults.
Override via environment variables or /srv/apps/1id/api/.env file.
"""

import os

# --- MySQL Database ---
MYSQL_HOST = os.environ.get("ONEID_DB_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("ONEID_DB_PORT", "3306"))
MYSQL_USER = os.environ.get("ONEID_DB_USER", "oneid")
# SECURITY: No hardcoded default -- must be set via environment variable or systemd unit
MYSQL_PASSWORD = os.environ.get("ONEID_DB_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("ONEID_DB_NAME", "oneid")

# --- Keycloak Admin API ---
KEYCLOAK_BASE_URL = os.environ.get("ONEID_KEYCLOAK_URL", "http://127.0.0.1:8088")
KEYCLOAK_REALM_NAME = "agents"
# SECURITY: No hardcoded defaults -- must be set via environment variable or systemd unit
KEYCLOAK_ADMIN_USER = os.environ.get("ONEID_KEYCLOAK_ADMIN_USER", "")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("ONEID_KEYCLOAK_ADMIN_PASSWORD", "")

# --- API Settings ---
API_VERSION = "0.2.0"
API_HOST = os.environ.get("ONEID_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("ONEID_API_PORT", "8180"))

# --- Rate Limiting (declared tier) ---
# Production values from spec: 1/hour, 10/day.
# Current values are relaxed for development/testing.
# TODO: Tighten to 1/hour, 10/day before public launch.
DECLARED_TIER_MAX_ENROLLMENTS_PER_IP_PER_HOUR = 20
DECLARED_TIER_MAX_ENROLLMENTS_PER_IP_PER_DAY = 100

# --- Enrollment Sessions ---
ENROLLMENT_SESSION_TTL_SECONDS = 300  # 5 minutes

# --- Identity ID Generation ---
INTERNAL_ID_PREFIX = "1id_"
INTERNAL_ID_LENGTH = 8  # chars after prefix, base36 alphanumeric

# --- Public URL (for response payloads) ---
PUBLIC_BASE_URL = os.environ.get("ONEID_PUBLIC_URL", "https://1id.com")
TOKEN_ENDPOINT = f"{PUBLIC_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token"
