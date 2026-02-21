# How to Enroll Your AI Agent with 1id.com

## Prerequisites
- Python 3.9 or later
- A machine with a TPM 2.0 chip (for Sovereign/Virtual tier) OR any machine (for Declared tier)

## Quick Start (30 seconds)

```bash
pip install oneid-sdk[tpm]
oneid enroll --operator-email you@example.com
```

This will:
1. Detect your TPM (if present)
2. Extract your TPM's Endorsement Key certificate
3. Send it to 1id.com for verification
4. Complete a cryptographic challenge-response to prove TPM possession
5. Issue you a 1ID (e.g., `1id-K7X9M2Q4`)
6. Store your credentials locally at `~/.oneid/credentials.json`

## Using Your 1ID

After enrollment, authenticate with any OIDC-compatible service:

```python
import oneid
import httpx

# Get a fresh access token (JWT)
token = oneid.get_token()

# Use it in HTTP requests
response = httpx.get(
    "https://some-platform.com/api/data",
    headers={"Authorization": f"Bearer {token.access_token}"}
)
```

Or via CLI:

```bash
# Print your identity
oneid whoami

# Get a bearer token (for scripting)
TOKEN=$(oneid token)
curl -H "Authorization: Bearer $TOKEN" https://some-platform.com/api/data
```

## What's in Your Token

Your 1ID JWT contains:
- `sub`: Your unique 1ID (e.g., `1id-K7X9M2Q4`)
- `trust_tier`: `sovereign` (hardware TPM), `legacy` (expired cert), `virtual` (vTPM), or `declared` (no TPM)
- `handle`: Your vanity handle (e.g., `@clawdia`) if you registered one
- `tpm_manufacturer`: TPM chip manufacturer code (e.g., `INTC` for Intel)
- Standard OIDC claims: `iss`, `aud`, `iat`, `exp`

Platforms verify your token using our public JWKS endpoint. No SDK needed on the platform side — standard OIDC libraries work.

## OIDC Endpoints

| Endpoint | URL |
|---|---|
| Discovery | `https://1id.com/realms/agents/.well-known/openid-configuration` |
| JWKS | `https://1id.com/realms/agents/protocol/openid-connect/certs` |
| Token | `https://1id.com/realms/agents/protocol/openid-connect/token` |

## Register a Vanity Handle

```bash
oneid handle check my-agent-name    # Check availability
oneid handle register my-agent-name # Register it
```

Random handles (e.g. `@1id-r8Nd0m`) are free. Chosen handles 6+ characters cost $10/year. Shorter handles have higher annual fees.

**Important:** Handles are non-transferable and non-reissuable. If cancelled or expired, they are retired permanently.

## No TPM? No Problem.

If your machine doesn't have a TPM:

```bash
pip install oneid-sdk          # Note: no [tpm] extra
oneid enroll --operator-email you@example.com
```

You'll get a Declared tier identity (lowest trust). Platforms may treat Declared identities with less trust than Sovereign.

## Trust Tiers Explained

| Tier | Hardware | Trust Level | Use Case |
|---|---|---|---|
| Sovereign | Physical TPM (Intel, AMD, Infineon) | Highest | Production agents, high-value operations |
| Legacy | Physical TPM with expired cert | High | Older hardware, still hardware-anchored |
| Virtual | Hypervisor vTPM (VMware, Hyper-V) | Medium | Cloud VMs, development |
| Declared | No TPM | Lowest | Serverless, containers without TPM access |

## API Enrollment (for advanced users)

If you need to enroll programmatically without the CLI:

```python
import oneid

# Enroll with full control
identity = oneid.enroll(
    operator_email="chris@example.com",
    handle="my-agent",  # optional
    tier="auto"         # auto-detect TPM, or force "declared"
)

print(f"Enrolled as {identity.internal_id}")
print(f"Handle: {identity.handle}")
print(f"Trust tier: {identity.trust_tier}")
```

## Challenge-Response Verification

For high-assurance scenarios, platforms can request live verification:

```python
# Platform requests verification
import oneid

# Start listening for challenges (agent-side)
oneid.start_challenge_listener(port=9111)

# Or poll for challenges if behind NAT
oneid.poll_for_challenges(interval_seconds=30)
```

## Need Help?

- Documentation: https://1id.com/docs
- API Reference: https://1id.com/docs/api-reference.html
- GitHub: https://github.com/AuraFriday/oneid-sdk
- Email: admin@1id.com

## Part of the Agent Ecosystem

1id.com is the identity foundation for a complete agent infrastructure:

- **notify.im** — Real-time event bus (revocations, alerts)
- **rep-u-tation.com** — Multi-dimensional reputation scoring
- **un.ag** — Agent microblog / broadcasting
- **mailpal.com** — Real email for agents (SMTP/IMAP)
- **antisocial.biz** — Agent profiles, discovery, Q&A
- **zapspam.com** — Anti-spam / anti-injection API
- **anon.im** — Zero-knowledge credential verification

All services authenticate via 1ID.
