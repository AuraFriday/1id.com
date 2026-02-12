#!/usr/bin/env python3
"""
Test script: verify that JWT tokens contain 1id custom claims.
Run on vaf: python3 test_token_claims.py
"""
import os
import urllib.request
import urllib.parse
import json
import base64
import sys

KC_URL = os.environ.get("ONEID_KEYCLOAK_URL", "http://127.0.0.1:8088")
ADMIN_USER = os.environ.get("ONEID_KEYCLOAK_ADMIN_USER", "")
ADMIN_PASS = os.environ.get("ONEID_KEYCLOAK_ADMIN_PASSWORD", "")

def get_admin_token():
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    }).encode()
    req = urllib.request.Request(f"{KC_URL}/realms/master/protocol/openid-connect/token", data=data)
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())["access_token"]

def kc_get(token, path):
    req = urllib.request.Request(f"{KC_URL}/admin/realms/agents{path}")
    req.add_header("Authorization", f"Bearer {token}")
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())

def decode_jwt_payload(jwt_token):
    """Decode JWT payload without verification (for inspection only)."""
    parts = jwt_token.split(".")
    payload_b64 = parts[1]
    # Add padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload_b64))

def main():
    print("=== 1id Keycloak SPI Token Claim Test ===\n")

    # 1. Get admin token
    print("1. Getting admin token...")
    admin_token = get_admin_token()
    print(f"   OK ({len(admin_token)} chars)")

    # 2. List clients in agents realm
    print("\n2. Listing clients in agents realm...")
    clients = kc_get(admin_token, "/clients?first=0&max=50")
    agent_clients = [c for c in clients if not c.get("clientId", "").startswith(("account", "admin", "broker", "realm", "security"))]
    print(f"   Total clients: {len(clients)}, Agent clients: {len(agent_clients)}")
    for c in agent_clients:
        print(f"   - {c['clientId']} (id={c['id'][:8]}...)")

    if not agent_clients:
        print("\n   No enrolled agents found! Run enrollment first.")
        print("   Alternatively, testing with a known client...")

        # Check if there's ANY confidential client we can test with
        for c in clients:
            if c.get("clientId") not in ("account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"):
                agent_clients.append(c)
        if not agent_clients:
            print("   No testable clients. Exiting.")
            sys.exit(1)

    # 3. For first agent client, get credentials and request token
    test_client = agent_clients[0]
    client_id_str = test_client["clientId"]
    client_internal_id = test_client["id"]

    print(f"\n3. Testing with client: {client_id_str}")

    # Get client secret
    secret_data = kc_get(admin_token, f"/clients/{client_internal_id}/client-secret")
    client_secret = secret_data.get("value")
    if not client_secret:
        print("   No client secret found. Generating one...")
        req = urllib.request.Request(
            f"{KC_URL}/admin/realms/agents/clients/{client_internal_id}/client-secret",
            method="POST"
        )
        req.add_header("Authorization", f"Bearer {admin_token}")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req)
        secret_data = json.loads(resp.read())
        client_secret = secret_data["value"]

    print(f"   Client secret: {client_secret[:8]}...")

    # 4. Request token using client_credentials
    print("\n4. Requesting access token via client_credentials...")
    token_data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id_str,
        "client_secret": client_secret
    }).encode()
    token_req = urllib.request.Request(
        f"{KC_URL}/realms/agents/protocol/openid-connect/token",
        data=token_data
    )
    token_resp = urllib.request.urlopen(token_req)
    token_result = json.loads(token_resp.read())
    access_token = token_result["access_token"]
    print(f"   Access token: {len(access_token)} chars")

    # 5. Decode and inspect claims
    print("\n5. Decoded JWT claims:")
    claims = decode_jwt_payload(access_token)
    for key, value in sorted(claims.items()):
        print(f"   {key}: {value}")

    # 6. Check for 1id claims
    print("\n6. 1id claim verification:")
    oneid_claims = ["trust_tier", "handle", "registered_at", "tpm_manufacturer", "ek_fingerprint_prefix"]
    found_count = 0
    for claim in oneid_claims:
        value = claims.get(claim)
        status = "PRESENT" if value is not None else "ABSENT"
        print(f"   {claim}: {status} = {value}")
        if value is not None:
            found_count += 1

    print(f"\n   {found_count}/{len(oneid_claims)} 1id claims found")

    # For declared tier, tpm_manufacturer and ek_fingerprint_prefix should be absent
    trust_tier = claims.get("trust_tier")
    if trust_tier == "declared":
        expected = {"trust_tier", "handle", "registered_at"}
        found = {c for c in oneid_claims if claims.get(c) is not None}
        if found == expected:
            print("   PASS: Correct claims for declared tier (no TPM claims)")
        else:
            print(f"   WARN: Expected {expected}, got {found}")
    elif trust_tier:
        print(f"   Trust tier: {trust_tier} (TPM claims should be present)")

    if found_count >= 3:
        print("\n=== PASS: 1id claims are being injected into tokens! ===")
    else:
        print("\n=== FAIL: Missing expected 1id claims ===")
        sys.exit(1)

if __name__ == "__main__":
    main()
