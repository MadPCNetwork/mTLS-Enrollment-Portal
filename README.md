# mTLS PKI Portal

A **Zero-Trust** self-service mTLS certificate management portal featuring:

- 🔐 **Zero-Knowledge Private Keys** - Keys never leave the browser
- 🌐 **Authentik OIDC Integration** - Single sign-on with group-based access control
- 📜 **Dynamic X.509 Subject Mapping** - OIDC claims automatically mapped to certificate attributes
- 👮 **Admin Console** - Global view, search, and revocation capabilities for administrators
- 📊 **Certificate Quotas** - Limit active certificates per user/CA with optional approval fallback
- 🔄 **Renewal Grace Period** - Seamless certificate rotation without downtime via configurable pre-expiry renewal windows
- ✅ **Approval Workflow** - Auto-approve for admins, manual approval for others
- 📧 **Email Notifications** - Automatic alerts for requests, approvals, denials, and renewal reminders
- 📦 **PKCS#12 Export** - One-click download with auto-generated password

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Network                                │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 Nginx (Port 80)                          │    │
│  │   ┌─────────────────────────────────────────────────┐   │    │
│  │   │   /api/* → Backend    │   /* → Static SPA       │   │    │
│  │   └─────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                       │
│              ┌───────────┴───────────┐                          │
│              ▼                       ▼                          │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │   FastAPI Backend   │  │   PostgreSQL DB     │              │
│  │   (Internal Only)   │  │   (Internal Only)   │              │
│  └─────────────────────┘  └─────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Clone and Configure

```bash
# Create secrets directory for CA certs
mkdir -p secrets

# Copy example configuration files
cp .env.example .env
cp config.example.yaml config.yaml
```

### 2. Generate CA Certificate (for testing)

```bash
# Create a self-signed CA for testing with REQUIRED extensions
# Authentik strictly validates CA certificates, so we must add specific extensions.

# 1. Generate Private Key
openssl genrsa -out secrets/internal-ca.key 4096

# 2. Generate Root CA Certificate
openssl req -x509 -new -nodes -key secrets/internal-ca.key \
    -sha256 -days 3650 -out secrets/internal-ca.crt \
    -subj "/C=US/O=Internal/CN=Internal Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,cRLSign,keyCertSign" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always,issuer"
```

### 3. Configure Authentik

1. Create a new **OAuth2/OpenID Provider** in Authentik
2. Set the **Redirect URI** to: `https://your-domain/callback`
3. Enable **PKCE** (S256)
4. Configure scopes: `openid`, `profile`, `email`, `groups`
5. Copy the **Client ID**

### 4. Update Configuration

Edit `.env`:

```bash
# OIDC Settings
OIDC_ISSUER=https://auth.example.com/application/o/pki/
OIDC_CLIENT_ID=your-client-id

# Database
POSTGRES_USER=pki
POSTGRES_PASSWORD=your-secure-password
POSTGRES_DB=pki
POSTGRES_HOST=db
POSTGRES_PORT=5432
```

Edit `config.yaml` for CA and subject mapping (see Configuration Guide below).

### 5. Start the Stack

```bash
docker-compose up -d
```

### 6. Access the Portal

Open `http://localhost` (or your configured domain) and sign in with Authentik.

---

## Configuration Guide

### Admin Access

Global admin privileges are configured in `config.yaml`. Members of these groups can search and revoke **ANY** certificate.

```yaml
admin_groups:
  - "ROOT"
  - "pki-admins"
```

### Subject Attributes Mapping

The `subject_attributes` section controls what goes into the X.509 certificate's Subject DN.

```yaml
subject_attributes:
  # Static values are ALWAYS included
  static:
    O: "Acme Corp"     # Organization
    C: "US"            # Country

  # Mapped values come from OIDC claims
  # If the claim is empty/missing, it's SKIPPED
  mapping:
    CN: "preferred_username"  # Common Name
    UID: "sub"               # User ID (unique identifier)
    GN: "given_name"         # Given Name
    SN: "family_name"        # Surname
    OU: "groups"             # Org Units (list → multiple entries)
```

#### Available X.509 Attributes

| Attribute | Description | Example |
|-----------|-------------|---------|
| `CN` | Common Name | `jdoe` |
| `O` | Organization | `Acme Corp` |
| `OU` | Organizational Unit | `Engineering` |
| `C` | Country (2-letter) | `US` |
| `ST` | State/Province | `California` |
| `L` | Locality/City | `San Francisco` |
| `GN` | Given Name | `John` |
| `SN` | Surname | `Doe` |
| `UID` | User ID | `auth0\|12345` |
| `EMAIL` | Email Address | `jdoe@example.com` |

#### Authentik OIDC Claims

Common claims available in Authentik:

| Claim | Description | Type |
|-------|-------------|------|
| `sub` | Unique user identifier | String |
| `preferred_username` | Username | String |
| `email` | Email address | String |
| `given_name` | First name | String |
| `family_name` | Last name | String |
| `name` | Full display name | String |
| `groups` | User's groups | Array of strings |
| `locale` | User's locale | String |

#### List Handling (Groups)

When a mapped claim is a list (like `groups`), the system creates **multiple RDNs**:

```
User Groups: ["Engineering", "DevOps"]
↓
Certificate Subject: OU=Engineering, OU=DevOps, CN=jdoe, O=Acme
```

#### Conditional Writing

If a mapped claim is:
- `null` → **SKIPPED**
- Empty string `""` → **SKIPPED**
- Empty array `[]` → **SKIPPED**
- Non-empty value → **INCLUDED**

This ensures certificates don't contain empty attributes.

---

### CA Rules Configuration

Control who can request certificates and whether approval is required:

```yaml
x509_cas:
  - id: "internal-mtls"
    name: "Internal Network Access"
    cert_path: "/secrets/ca.crt"
    key_path: "/secrets/ca.key"
    
    rules:
      # First matching rule wins
      - oidc_groups: ["admins"]
        auto_approve: true
        max_ttl: "8760h"  # 1 year
        renewal_grace_period: "720h"  # Allow renewal 30 days before expiry
        renewal_notification_email: true  # Notify owner when renewal window opens

      # Staff need approval from security team
      - oidc_groups: ["staff", "employees"]
        auto_approve: false
        approver_groups: ["security"]
        max_active_certs: 1            # Limit to 1 active cert
        allow_request_over_quota: true # Allow request but force manual approval if over quota
        max_ttl: "720h"                # 30 days
        renewal_grace_period: "168h"   # Allow renewal 7 days before expiry
        renewal_notification_email: true
```

**Rule Evaluation:**
1. Rules are checked in order
2. First rule where user has a matching group is applied
3. If no rules match, user cannot access that CA

**TTL Formats:**
- `720h` - 720 hours (30 days)
- `8760h` - 8760 hours (1 year)

#### Renewal Grace Period

The `renewal_grace_period` setting controls how early a user can request a new certificate before their current one expires, without the expiring certificate counting against their quota.

This is essential for seamless certificate rotation: without a grace period, a user with `max_active_certs: 1` would need to either revoke their current certificate (losing access) or wait for it to expire before requesting a new one.

**How it works:**
- When a certificate is within the grace period of its expiry, it is **excluded from the quota count**
- This allows the user to request a new certificate while the old one is still valid
- The old certificate remains valid until its actual expiry date
- The grace period only affects quota counting, not certificate validity

**Example:** A rule with `max_ttl: "720h"` (30 days) and `renewal_grace_period: "168h"` (7 days) means:
- A user with 1 active cert (30-day lifetime) can request a new cert starting 7 days before expiry
- During those 7 days, the expiring cert does not count against `max_active_certs`
- The user effectively has 2 valid certs for up to 7 days during the transition

**Recommended values:**
| Certificate TTL | Suggested Grace Period | Ratio |
|----------------|----------------------|-------|
| `8760h` (1 year) | `720h` (30 days) | ~8% |
| `720h` (30 days) | `168h` (7 days) | ~23% |
| `168h` (7 days) | `24h` (1 day) | ~14% |

Set to `"0h"` or omit to disable the grace period (default behavior).

#### Renewal Notification Emails

When `renewal_notification_email: true` is set on a rule, the portal sends a **one-time email** to the certificate owner when their certificate enters the renewal grace period. This proactively reminds users to renew early and install a new certificate to minimize any risk of loss of access.

**Requirements:**
- SMTP must be enabled globally (`SMTP_ENABLED=true`)
- The rule must have a `renewal_grace_period` greater than `"0h"`
- The certificate owner must have an email address on file (from OIDC)

**Behavior:**
- A background task checks for eligible certificates on a configurable interval (default: every hour)
- Each certificate is only notified **once** (tracked in the database)
- The email includes the certificate serial number, expiry date, days remaining, and a link to the portal
- The urgency badge in the email adapts: blue for early window, amber at 7 days, red at 3 days

**Configuration per rule:**

```yaml
rules:
  - oidc_groups: ["admins"]
    renewal_grace_period: "720h"
    renewal_notification_email: true   # Enable reminders for this group

  - oidc_groups: ["contractors"]
    renewal_grace_period: "24h"
    renewal_notification_email: false  # Disable reminders for this group
```

**Tuning the check interval** (optional, in `.env`):

```bash
RENEWAL_CHECK_INTERVAL=3600  # seconds (default: 3600 = 1 hour)
```



### Email Notifications

Configure SMTP in `.env` to enable notifications for:
- **Approvers**: New pending requests
- **Requesters**: Approval/Denial status updates
- **Certificate Owners**: Renewal reminders when certificates enter the grace period

```bash
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_user
SMTP_PASSWORD=your_password
SMTP_SERVER_NAME=pki.example.com  # Required for Google Relay
```

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/cas` | GET | Yes | List available CAs |
| `/api/v1/requests` | GET | Yes | List user's requests |
| `/api/v1/request` | POST | Yes | Create certificate request |
| `/api/v1/sign/{id}` | POST | Yes | Submit CSR, get signed cert |
| `/api/v1/certificates` | GET | Yes | List user's certificates |
| `/api/v1/revoke/{id}` | POST | Yes | Revoke a certificate |
| `/api/v1/pending` | GET | Yes | List pending approvals |
| `/api/v1/approve/{id}` | POST | Yes | Approve a request |
| `/api/v1/deny/{id}` | POST | Yes | Deny a request |
| `/api/v1/crl/{ca_id}` | GET | No | Get CRL (public) |
| `/api/v1/ca/{ca_id}` | GET | No | Get CA Certificate (public) |
| `/api/v1/admin/certificates`| GET | Admin | List/Search all certificates |
| `/api/v1/admin/revoke/{id}` | POST | Admin | Force revoke any certificate |

---

## Security Considerations

### Zero-Knowledge Private Keys

1. **Key Generation**: RSA-4096 keys are generated in the browser using WebCrypto API
2. **CSR Creation**: The CSR is created locally; the private key never leaves the browser
3. **Subject Override**: The backend completely ignores the CSR's subject and enforces the mapped OIDC claims
4. **PKCS#12 Bundle**: The certificate and private key are bundled client-side with a random password

### Session Security

- Uses OIDC Authorization Code flow with PKCE
- Tokens stored in sessionStorage (not localStorage)
- Bearer tokens validated against Authentik's JWKS

### Reverse Proxy Compatibility

Designed to work behind:
- Cloudflare Zero Trust
- Nginx Proxy Manager
- Traefik
- Any TLS-terminating reverse proxy

---

## Development

### Local Development Without Docker

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (serve with any static server)
cd frontend/src
python -m http.server 3000
```

### Running Tests

```bash
cd backend
pytest tests/ -v
```

---

## Troubleshooting

### "OIDC configuration not found"

Ensure `config/oidc-config.json` exists and is mounted correctly.

### "Invalid token" errors

1. Check that the issuer URL matches exactly (including trailing slash)
2. Verify the client_id is correct
3. Ensure Authentik's clock is synchronized

### Certificate generation fails

1. Check CA certificate and key paths
2. Verify CA key is readable by the container
3. Check backend logs: `docker-compose logs backend`

---

## Revocation & CRL

The portal provides a dynamic Certificate Revocation List (CRL) for each CA.

**Endpoint:** `GET /api/v1/crl/{ca_id}`

### Configuring Nginx for mTLS Revocation Checks

Nginx requires the CRL to be a file on disk. You should set up a cron job to fetch the CRL periodically and reload Nginx.

1. **Add CRL to Nginx Config:**

```nginx
server {
    listen 443 ssl;
    server_name internal.example.com;

    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_crl /etc/nginx/certs/ca.crl;  # Point to the CRL file
    ssl_verify_client on;

    # ... other config ...
}
```

2. **Setup Cron Job (e.g., every hour):**

```bash
#!/bin/bash
# Fetch latest CRL
curl -s -o /etc/nginx/certs/ca.crl.tmp https://pki.example.com/api/v1/crl/internal-mtls

# Verify it's a valid CRL before replacing
openssl crl -in /etc/nginx/certs/ca.crl.tmp -noout
if [ $? -eq 0 ]; then
    mv /etc/nginx/certs/ca.crl.tmp /etc/nginx/certs/ca.crl
    systemctl reload nginx
fi
```

---

## License

MIT License - See LICENSE file for details
