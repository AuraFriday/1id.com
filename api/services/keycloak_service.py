"""
1id.com -- Keycloak Admin API Service

Creates confidential clients in the 'agents' realm for each enrolled identity.
Uses Keycloak Admin REST API over localhost (:8088).

Ref: https://www.keycloak.org/docs-api/latest/rest-api/
"""

import httpx
import config
import logging

logger = logging.getLogger("oneid.keycloak")

_cached_admin_token = None
_cached_admin_token_expires_at = 0


async def _get_admin_access_token():
  """
  Get an admin access token from Keycloak master realm.
  Caches the token until near expiry.
  """
  global _cached_admin_token, _cached_admin_token_expires_at

  import time
  now = time.time()
  if _cached_admin_token and now < _cached_admin_token_expires_at - 30:
    return _cached_admin_token

  async with httpx.AsyncClient() as http_client:
    response = await http_client.post(
      f"{config.KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token",
      data={
        "grant_type": "client_credentials",
        "client_id": "admin-cli",
        "username": config.KEYCLOAK_ADMIN_USER,
        "password": config.KEYCLOAK_ADMIN_PASSWORD,
        "grant_type": "password",
      },
    )
    response.raise_for_status()
    token_data = response.json()
    _cached_admin_token = token_data["access_token"]
    _cached_admin_token_expires_at = now + token_data.get("expires_in", 60)
    return _cached_admin_token


_oneid_claims_scope_id_cache = None


async def _get_oneid_claims_scope_id(http_client, admin_token):
  """
  Look up the 'oneid-claims' client scope ID in the agents realm.
  Caches the result since the scope ID doesn't change.
  """
  global _oneid_claims_scope_id_cache
  if _oneid_claims_scope_id_cache:
    return _oneid_claims_scope_id_cache

  scopes_response = await http_client.get(
    f"{config.KEYCLOAK_BASE_URL}/admin/realms/{config.KEYCLOAK_REALM_NAME}/client-scopes",
    headers={"Authorization": f"Bearer {admin_token}"},
  )
  scopes_response.raise_for_status()
  for scope in scopes_response.json():
    if scope.get("name") == "oneid-claims":
      _oneid_claims_scope_id_cache = scope["id"]
      return _oneid_claims_scope_id_cache

  logger.warning("oneid-claims scope not found in Keycloak agents realm")
  return None


async def _assign_oneid_claims_scope_to_client(http_client, admin_token, keycloak_client_uuid):
  """
  Assign the 'oneid-claims' scope to a client so JWT tokens contain
  1id custom claims (trust_tier, handle, registered_at, etc).
  """
  scope_id = await _get_oneid_claims_scope_id(http_client, admin_token)
  if not scope_id:
    return

  assign_response = await http_client.put(
    f"{config.KEYCLOAK_BASE_URL}/admin/realms/{config.KEYCLOAK_REALM_NAME}/clients/{keycloak_client_uuid}/default-client-scopes/{scope_id}",
    headers={"Authorization": f"Bearer {admin_token}"},
  )
  if assign_response.status_code == 204:
    logger.info("Assigned oneid-claims scope to client %s", keycloak_client_uuid)
  else:
    logger.warning(
      "Failed to assign oneid-claims scope to client %s: HTTP %s",
      keycloak_client_uuid,
      assign_response.status_code,
    )


async def create_confidential_client_for_agent(
  agent_internal_id,
  agent_display_name=None,
):
  """
  Create a new confidential client in the 'agents' realm for an enrolled agent.

  Returns: dict with 'client_id' and 'client_secret'.
  """
  admin_token = await _get_admin_access_token()

  client_id_value = agent_internal_id  # e.g. "1id_K7X9M2Q4"
  display_name = agent_display_name or f"1id Agent: {agent_internal_id}"

  client_representation = {
    "clientId": client_id_value,
    "name": display_name,
    "enabled": True,
    "clientAuthenticatorType": "client-secret",
    "serviceAccountsEnabled": True,  # enables client_credentials grant
    "publicClient": False,  # confidential client
    "protocol": "openid-connect",
    "standardFlowEnabled": False,  # no browser login needed
    "directAccessGrantsEnabled": False,
    "attributes": {
      "1id.trust_tier": "declared",  # will be updated for sovereign
      "1id.internal_id": agent_internal_id,
    },
  }

  async with httpx.AsyncClient() as http_client:
    # Create the client
    create_response = await http_client.post(
      f"{config.KEYCLOAK_BASE_URL}/admin/realms/{config.KEYCLOAK_REALM_NAME}/clients",
      json=client_representation,
      headers={"Authorization": f"Bearer {admin_token}"},
    )
    create_response.raise_for_status()

    # The location header contains the new client's UUID
    location_header = create_response.headers.get("Location", "")
    keycloak_client_uuid = location_header.rstrip("/").split("/")[-1]

    # Assign the oneid-claims default scope so JWT tokens contain 1id claims
    await _assign_oneid_claims_scope_to_client(
      http_client, admin_token, keycloak_client_uuid
    )

    # Fetch the client secret
    secret_response = await http_client.get(
      f"{config.KEYCLOAK_BASE_URL}/admin/realms/{config.KEYCLOAK_REALM_NAME}/clients/{keycloak_client_uuid}/client-secret",
      headers={"Authorization": f"Bearer {admin_token}"},
    )
    secret_response.raise_for_status()
    secret_data = secret_response.json()

    logger.info(
      "Created Keycloak client for agent %s (uuid=%s)",
      agent_internal_id,
      keycloak_client_uuid,
    )

    return {
      "client_id": client_id_value,
      "client_secret": secret_data["value"],
    }


async def get_initial_tokens_for_agent(client_id, client_secret):
  """
  Use client_credentials grant to get the agent's initial access + refresh tokens.
  """
  async with httpx.AsyncClient() as http_client:
    response = await http_client.post(
      f"{config.KEYCLOAK_BASE_URL}/realms/{config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
      data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
      },
    )
    response.raise_for_status()
    return response.json()
