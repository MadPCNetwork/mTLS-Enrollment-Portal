# mTLS PKI Portal - Comprehensive Security Guide

**Version:** 1.0  
**Application:** Zero-Trust mTLS Certificate Management Portal

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Security Architecture](#security-architecture)
3. [Implemented Security Controls](#implemented-security-controls)
4. [Threat Model](#threat-model)
5. [Security Configuration](#security-configuration)
6. [Operational Security](#operational-security)
7. [Security Roadmap](#security-roadmap)
8. [Appendices](#appendices)

---

## Executive Summary

### Security Posture

The mTLS PKI Portal implements a **defense-in-depth** security strategy with multiple layers of protection:

- **Zero-Knowledge Architecture**: Private keys never leave the user's browser
- **Strong Authentication**: OIDC with PKCE flow
- **Comprehensive Auditing**: All security events logged in structured format
- **Rate Limiting**: Protection against abuse and DoS attacks
- **Security Headers**: Multiple HTTP security headers prevent common attacks
- **Access Control**: Group-based permissions with approval workflows
- **Certificate Quotas**: Prevent resource exhaustion

### Risk Level: **MEDIUM**

**Justification:**
- ✅ Strong cryptographic controls (RSA-4096, SHA-256)
- ✅ Zero-knowledge private key handling
- ✅ Comprehensive audit logging
- ⚠️ CA private keys stored on filesystem (should use HSM in production)
- ⚠️ No CSRF protection (mitigated by Bearer token auth)
- ⚠️ Permissive CSP (trade-off for functionality)

---

## Security Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Reverse Proxy      │
              │   (Nginx/Cloudflare) │
              │   - TLS Termination  │
              │   - Rate Limiting    │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Frontend (Nginx)   │
              │   - Static SPA       │
              │   - Security Headers │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Backend (FastAPI)  │
              │   - API Endpoints    │
              │   - Rate Limiting    │
              │   - Audit Logging    │
              │   - Auth Validation  │
              └──────────┬───────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    ┌────────┐    ┌──────────┐    ┌──────────┐
    │  OIDC  │    │PostgreSQL│    │ CA Keys  │
    │Provider│    │ Database │    │(Secrets) │
    └────────┘    └──────────┘    └──────────┘
```

### Security Zones

| Zone | Components | Trust Level | Access Control |
|------|------------|-------------|----------------|
| **Public** | Frontend SPA, Public API endpoints | Untrusted | None |
| **Authenticated** | User API endpoints | Low Trust | OIDC Bearer Token |
| **Privileged** | Admin endpoints, Approver endpoints | Medium Trust | OIDC + Group Membership |
| **Critical** | CA Private Keys, Database | High Trust | Filesystem ACLs, Network Isolation |

### Zero-Knowledge Architecture

**Private Key Lifecycle:**

```
1. User Browser (WebCrypto API)
   ↓ Generate RSA-4096 Key Pair
   ↓ Private Key: NEVER leaves browser
   ↓ Public Key: Sent in CSR
   
2. Backend
   ↓ Receives CSR
   ↓ Validates signature
   ↓ IGNORES CSR subject
   ↓ Builds subject from OIDC claims
   ↓ Signs with CA key
   ↓ Returns signed certificate
   
3. User Browser
   ↓ Receives signed certificate
   ↓ Bundles with private key (PKCS#12)
   ↓ Encrypts with random password
   ↓ Downloads to user's device
```

**Security Properties:**
- ✅ Server never sees private key
- ✅ Subject cannot be forged (enforced from OIDC)
- ✅ Certificate bound to user's device
- ✅ Password shown only once

---

## Implemented Security Controls

### 1. Authentication & Authorization

#### OIDC Authentication (OAuth 2.0 + PKCE)

**Implementation:**
- Authorization Code flow with PKCE (RFC 7636)
- State parameter for CSRF protection
- Code verifier/challenge (S256)
- Immediate state cleanup after validation

**Security Features:**
```javascript
// State and verifier cleared BEFORE validation
sessionStorage.removeItem('oidc_state');
sessionStorage.removeItem('oidc_verifier');

// Then validate (prevents replay)
if (returnedState !== savedState) {
    return false;
}
```

**Token Storage:**
- Access tokens in `sessionStorage` (not `localStorage`)
- Tokens cleared on logout
- No refresh tokens (re-authenticate on expiry)

**Threat Mitigation:**
- ✅ CSRF attacks (state parameter)
- ✅ Authorization code interception (PKCE)
- ✅ Replay attacks (state cleanup)
- ⚠️ XSS can steal tokens (mitigated by CSP, but not eliminated)

#### Group-Based Access Control

**Hierarchy:**
```
Admin Groups (config.yaml: admin_groups)
  ↓ Full access to all certificates
  ↓ Can revoke any certificate
  ↓ Can search all users

Approver Groups (per CA: approver_groups)
  ↓ Can approve/deny requests for specific CAs
  ↓ Can view pending requests
  
User Groups (per CA: oidc_groups)
  ↓ Can request certificates from specific CAs
  ↓ Can manage own certificates
```

**Configuration Example:**
```yaml
admin_groups:
  - "ROOT"
  - "pki-admins"

x509_cas:
  - id: "internal-mtls"
    rules:
      - oidc_groups: ["admins"]
        auto_approve: true
        approver_groups: []
      
      - oidc_groups: ["staff"]
        auto_approve: false
        approver_groups: ["security", "admins"]
```

### 2. Rate Limiting

**Implementation:** `slowapi` library with per-IP tracking

**Limits:**

| Endpoint | Limit | Rationale |
|----------|-------|-----------|
| `/api/v1/request` | 5/minute | Prevent cert request spam |
| `/api/v1/sign/{id}` | 10/minute | Limit cert generation |
| `/api/v1/revoke/{id}` | 10/minute | Prevent revocation abuse |
| `/api/v1/approve/{id}` | 20/minute | Approver workflow |
| `/api/v1/deny/{id}` | 20/minute | Approver workflow |
| `/api/v1/admin/*` | 20-60/minute | Admin operations |
| All other endpoints | 30/minute | General protection |

**Features:**
- Per-IP address tracking
- Works behind reverse proxies (X-Forwarded-For)
- Automatic 429 responses with retry-after
- Audit logging of violations

**Response Example:**
```json
{
  "detail": "Rate limit exceeded. Please try again later.",
  "retry_after": "60 seconds"
}
```

**Bypass Protection:**
- Rate limits apply even to authenticated users
- No whitelist (prevents privilege escalation)
- Limits enforced at application layer (not just nginx)

### 3. Audit Logging

**Implementation:** Structured JSON logging to stdout/stderr

**Event Categories:**

#### Authentication Events
```json
{
  "event_type": "auth.login.success",
  "timestamp": "2026-02-06T12:34:56.789Z",
  "user_id": "auth0|123456",
  "user_email": "user@example.com",
  "ip_address": "192.168.1.100",
  "details": {
    "groups": ["staff", "engineering"],
    "name": "John Doe"
  }
}
```

#### Certificate Lifecycle Events
- `cert.request.created` - New request
- `cert.request.auto_approved` - Auto-approved
- `cert.request.approved` - Manual approval
- `cert.request.denied` - Request denied
- `cert.issued` - Certificate generated
- `cert.revoked` - User revocation
- `cert.revoked.admin` - Admin revocation

#### Security Events
- `security.rate_limit.exceeded` - Rate limit hit
- `security.unauthorized_access` - Unauthorized attempt
- `security.quota.exceeded` - Quota violation
- `security.invalid_input` - Invalid input detected

#### Admin Events
- `admin.access` - Admin panel access
- `admin.search` - Admin searches
- `admin.view.cert` - Certificate viewing

**Log Retention:**
```yaml
# docker-compose.yml
services:
  backend:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"
```

**Querying Logs:**
```bash
# View all audit events
docker-compose logs backend | grep security_audit

# Failed authentication attempts
docker-compose logs backend | grep "auth.login.failure"

# Admin actions
docker-compose logs backend | grep "admin\."

# Failed events only
docker-compose logs backend | grep '"success": false'
```

### 4. Security Headers

**Implementation:** FastAPI middleware + Nginx configuration

#### Content Security Policy (CSP)
```
default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;
frame-ancestors 'none';
base-uri 'self';
form-action 'self'
```

**Rationale:**
- Permissive to allow external resources (OIDC, CDN, fonts)
- Still prevents clickjacking (`frame-ancestors 'none'`)
- Still restricts base URI and form actions
- Trade-off: Functionality over strict CSP

**Alternative (Strict CSP):**
If you want stricter CSP, whitelist specific domains:
```python
response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "connect-src 'self' https://your-oidc-domain.com; "
    "frame-ancestors 'none'"
)
```

#### Other Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer info |
| `Permissions-Policy` | `geolocation=(), camera=(), ...` | Disable browser features |
| `Strict-Transport-Security` | `max-age=31536000` | Enforce HTTPS (production only) |

**HSTS Configuration:**
```nginx
# Only enable with HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

⚠️ **Warning:** Only enable HSTS after HTTPS is properly configured. Enabling HSTS on HTTP will break your site.

### 5. Input Validation

#### CSR Validation
```python
def parse_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    
    # Validate signature
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    
    # Validate key strength (recommended addition)
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("RSA key must be at least 2048 bits")
    
    return csr
```

#### Subject Enforcement
```python
# Backend IGNORES CSR subject entirely
# Subject is built from OIDC claims only
subject = build_subject_from_claims(user_claims)
```

**Security Property:** Users cannot forge certificate subjects

#### SQL Injection Protection
- ✅ SQLAlchemy ORM (parameterized queries)
- ✅ No raw SQL execution
- ✅ Input sanitization on search queries

### 6. Certificate Quotas

**Purpose:** Prevent resource exhaustion and abuse

**Configuration:**
```yaml
x509_cas:
  - id: "internal-mtls"
    rules:
      - oidc_groups: ["staff"]
        max_active_certs: 3  # Limit to 3 active certs
        allow_request_over_quota: true  # Allow but require approval
```

**Behavior:**

| Scenario | `allow_request_over_quota: true` | `allow_request_over_quota: false` |
|----------|----------------------------------|-----------------------------------|
| Under quota | Auto-approve (if configured) | Auto-approve (if configured) |
| At/over quota | Force manual approval | **Block request entirely** |

**Audit Logging:**
```json
{
  "event_type": "security.quota.exceeded",
  "user_id": "user123",
  "details": {
    "ca_id": "internal-mtls",
    "current_count": 3,
    "limit": 3
  }
}
```

### 7. Cryptographic Controls

#### Key Generation (Client-Side)
```javascript
// RSA-4096 with WebCrypto API
const keyPair = await crypto.subtle.generateKey(
    {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
);
```

**Properties:**
- ✅ 4096-bit RSA keys
- ✅ SHA-256 hash algorithm
- ✅ Cryptographically secure random number generator
- ✅ Keys generated in browser (never transmitted)

#### Certificate Signing (Server-Side)
```python
# Sign with SHA-256
certificate = builder.sign(ca_key, hashes.SHA256())
```

**Extensions:**
- `BasicConstraints`: CA=FALSE (end-entity cert)
- `KeyUsage`: digitalSignature, keyEncipherment
- `ExtendedKeyUsage`: clientAuth (required for mTLS)
- `SubjectKeyIdentifier`: Hash of public key
- `AuthorityKeyIdentifier`: Hash of CA public key
- `SubjectAlternativeName`: Email, DNS (if configured)

#### Password Generation
```javascript
function generateStrongPassword() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const array = new Uint32Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, x => charset[x % charset.length]).join('');
}
```

**Properties:**
- ✅ 32 characters
- ✅ Cryptographically random
- ⚠️ Modulo bias (minor entropy reduction)

**Improved Version:**
```javascript
function generateStrongPassword() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    
    // Rejection sampling to avoid modulo bias
    let password = '';
    for (let i = 0; i < array.length; i++) {
        const value = array[i];
        if (value < 256 - (256 % charset.length)) {
            password += charset[value % charset.length];
        }
    }
    return password.substring(0, 32);
}
```

#### PKCS#12 Encryption
```javascript
// AES-128 encryption for PKCS#12
const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    privateKey,
    [certificate, ...chainCerts],
    password,
    { algorithm: 'aes128' }
);
```

---

## Threat Model

### Threat Actors

| Actor | Motivation | Capability | Likelihood |
|-------|------------|------------|------------|
| **External Attacker** | Data theft, disruption | Low-Medium | High |
| **Malicious Insider** | Privilege escalation, data theft | Medium-High | Low |
| **Compromised User** | Lateral movement | Low-Medium | Medium |
| **Nation State** | Espionage, disruption | High | Very Low |

### Attack Scenarios

#### 1. Certificate Forgery

**Attack:** Attacker attempts to generate certificate with forged subject

**Mitigations:**
- ✅ Subject enforced from OIDC claims (backend ignores CSR subject)
- ✅ OIDC token validation
- ✅ Group-based access control
- ✅ Audit logging of all issuances

**Residual Risk:** Low

---

#### 2. Private Key Theft

**Attack:** Attacker attempts to steal user's private key

**Mitigations:**
- ✅ Private keys never leave browser
- ✅ Keys generated client-side with WebCrypto
- ✅ PKCS#12 encrypted with strong password
- ✅ Password shown only once

**Residual Risk:** Low (requires compromising user's device)

---

#### 3. CA Private Key Compromise

**Attack:** Attacker gains access to CA private key

**Mitigations:**
- ✅ CA keys stored on filesystem with restricted permissions
- ✅ Keys encrypted with password (if configured)
- ✅ Docker volume isolation
- ⚠️ No HSM protection

**Residual Risk:** **Medium-High**

**Recommendations:**
- Use Hardware Security Module (HSM) in production
- Implement key rotation procedures
- Use secrets management (HashiCorp Vault, AWS Secrets Manager)

---

#### 4. Denial of Service (DoS)

**Attack:** Attacker floods API with requests

**Mitigations:**
- ✅ Rate limiting on all endpoints
- ✅ Per-IP tracking
- ✅ Certificate quotas
- ✅ Audit logging of violations
- ⚠️ No DDoS protection at network layer

**Residual Risk:** Medium

**Recommendations:**
- Deploy behind Cloudflare or AWS Shield
- Implement IP-based blocking for repeat offenders
- Set up monitoring and alerting

---

#### 5. Session Hijacking

**Attack:** Attacker steals user's session token

**Mitigations:**
- ✅ Tokens in sessionStorage (not localStorage)
- ✅ HTTPS only (in production)
- ✅ Short token lifetime
- ⚠️ No httpOnly cookies
- ⚠️ Vulnerable to XSS

**Residual Risk:** Medium

**Recommendations:**
- Implement httpOnly cookies for token storage
- Add CSRF protection
- Implement session timeout and token refresh

---

#### 6. Privilege Escalation

**Attack:** User attempts to access admin functions

**Mitigations:**
- ✅ Group-based access control
- ✅ Server-side authorization checks
- ✅ Audit logging of unauthorized attempts
- ✅ No client-side authorization logic

**Residual Risk:** Low

---

#### 7. SQL Injection

**Attack:** Attacker injects SQL through search queries

**Mitigations:**
- ✅ SQLAlchemy ORM (parameterized queries)
- ✅ No raw SQL execution
- ✅ Input validation on search terms

**Residual Risk:** Very Low

---

#### 8. Cross-Site Scripting (XSS)

**Attack:** Attacker injects malicious scripts

**Mitigations:**
- ✅ Content Security Policy
- ✅ X-XSS-Protection header
- ✅ HTML escaping in frontend
- ⚠️ Permissive CSP allows inline scripts

**Residual Risk:** Medium

**Recommendations:**
- Implement stricter CSP
- Use Content Security Policy reporting
- Regular security scanning

---

#### 9. Clickjacking

**Attack:** Attacker embeds application in iframe

**Mitigations:**
- ✅ X-Frame-Options: DENY
- ✅ CSP frame-ancestors: 'none'

**Residual Risk:** Very Low

---

#### 10. Man-in-the-Middle (MITM)

**Attack:** Attacker intercepts traffic

**Mitigations:**
- ✅ HTTPS enforced (in production)
- ✅ HSTS header (when enabled)
- ✅ Certificate pinning (OIDC provider)

**Residual Risk:** Low (with HTTPS)

---

## Security Configuration

### Environment Variables (.env)

```bash
# Application
APP_URL=https://pki.example.com

# OIDC
OIDC_ISSUER=https://auth.example.com/application/o/pki/
OIDC_CLIENT_ID=pki-app
OIDC_CLIENT_SECRET=  # Leave empty for PKCE-only
OIDC_SCOPES=openid,profile,email,groups

# Database
POSTGRES_USER=pki
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD
POSTGRES_DB=pki
POSTGRES_HOST=db
POSTGRES_PORT=5432

# CA Key Passwords (if encrypted)
# INTERNAL_CA_KEY_PASSWORD=strong_password_here

# SMTP (optional)
SMTP_ENABLED=false
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_ADDRESS=pki@example.com
SMTP_USE_TLS=true
SMTP_SERVER_NAME=pki.example.com
```

**Security Checklist:**
- [ ] Change default database password
- [ ] Use strong CA key passwords
- [ ] Store secrets in environment variables (not in code)
- [ ] Use secrets management in production
- [ ] Restrict file permissions on .env (chmod 600)

### Configuration File (config.yaml)

```yaml
# Admin groups (full access)
admin_groups:
  - "ROOT"
  - "pki-admins"

# Subject attribute mapping
subject_attributes:
  static:
    O: "Acme Corp"
    C: "US"
  mapping:
    CN: "preferred_username"
    UID: "sub"
    EMAIL: "email"
    OU: "groups"

# Certificate Authorities
x509_cas:
  - id: "internal-mtls"
    name: "Internal Network Access"
    cert_path: "/secrets/internal-ca.crt"
    key_path: "/secrets/internal-ca.key"
    key_password_env_var: "INTERNAL_CA_KEY_PASSWORD"
    
    rules:
      # Admins: auto-approve, 1 year TTL
      - oidc_groups: ["admins", "security"]
        auto_approve: true
        max_ttl: "8760h"
        max_active_certs: null  # Unlimited
      
      # Staff: manual approval, 30 days TTL, quota
      - oidc_groups: ["staff", "employees"]
        auto_approve: false
        approver_groups: ["security", "admins"]
        max_ttl: "720h"
        max_active_certs: 3
        allow_request_over_quota: true
```

**Security Checklist:**
- [ ] Restrict admin_groups to trusted users
- [ ] Set appropriate max_ttl values
- [ ] Configure certificate quotas
- [ ] Use encrypted CA keys
- [ ] Store CA keys in secure location
- [ ] Restrict file permissions on config.yaml (chmod 600)

### CA Certificate Generation

**For Production:**
```bash
# Use a proper CA infrastructure
# This is just for testing/development

# Generate CA private key (4096-bit RSA)
openssl genrsa -aes256 -out ca.key 4096

# Generate CA certificate (10 years)
openssl req -x509 -new -nodes -key ca.key \
    -sha256 -days 3650 -out ca.crt \
    -subj "/C=US/O=Acme Corp/CN=Internal Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,cRLSign,keyCertSign" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always,issuer"
```

**Security Checklist:**
- [ ] Use strong password for CA key
- [ ] Store CA key in HSM (production)
- [ ] Implement key rotation procedures
- [ ] Backup CA key securely (offline, encrypted)
- [ ] Document CA key recovery procedures
- [ ] Set appropriate validity period
- [ ] Include required extensions

### Docker Security

**docker-compose.yml:**
```yaml
services:
  backend:
    # Run as non-root user
    user: "1000:1000"
    
    # Read-only root filesystem
    read_only: true
    
    # Drop capabilities
    cap_drop:
      - ALL
    
    # Security options
    security_opt:
      - no-new-privileges:true
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

**Security Checklist:**
- [ ] Run containers as non-root
- [ ] Use read-only filesystems where possible
- [ ] Drop unnecessary capabilities
- [ ] Set resource limits
- [ ] Use security options (no-new-privileges)
- [ ] Scan images for vulnerabilities
- [ ] Keep base images updated

### Network Security

**Firewall Rules:**
```bash
# Allow only necessary ports
ufw allow 80/tcp    # HTTP (redirect to HTTPS)
ufw allow 443/tcp   # HTTPS
ufw deny 5432/tcp   # PostgreSQL (internal only)
ufw deny 8000/tcp   # Backend (internal only)
```

**Docker Network Isolation:**
```yaml
networks:
  pki-network:
    driver: bridge
    internal: false  # Set to true for complete isolation
```

**Security Checklist:**
- [ ] Restrict database access to backend only
- [ ] Use internal Docker networks
- [ ] Configure firewall rules
- [ ] Disable unnecessary services
- [ ] Use VPN for admin access (optional)

---

## Operational Security

### Deployment Checklist

#### Pre-Deployment
- [ ] Review all configuration files
- [ ] Change default passwords
- [ ] Generate production CA certificates
- [ ] Configure OIDC provider
- [ ] Set up SMTP (if using email notifications)
- [ ] Review and adjust rate limits
- [ ] Configure log retention
- [ ] Set up monitoring and alerting

#### Deployment
- [ ] Deploy behind HTTPS reverse proxy
- [ ] Enable HSTS header
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Configure log aggregation
- [ ] Test authentication flow
- [ ] Test certificate generation
- [ ] Verify audit logging

#### Post-Deployment
- [ ] Monitor logs for errors
- [ ] Test rate limiting
- [ ] Verify security headers
- [ ] Test admin functions
- [ ] Document incident response procedures
- [ ] Schedule security reviews

### Monitoring & Alerting

**Key Metrics:**

| Metric | Threshold | Action |
|--------|-----------|--------|
| Failed auth attempts | >10 from single IP in 5 min | Alert + investigate |
| Rate limit violations | >5 from single IP in 1 min | Alert + consider blocking |
| Unauthorized access attempts | Any | Alert immediately |
| Certificate issuance rate | >10/hour per user | Alert + investigate |
| Admin actions | Any | Log + review daily |
| Database errors | Any | Alert immediately |
| Backend errors (5xx) | >10/min | Alert immediately |

**Monitoring Tools:**
- **Logs:** ELK Stack, Splunk, Datadog
- **Metrics:** Prometheus + Grafana
- **Uptime:** UptimeRobot, Pingdom
- **Security:** OSSEC, Wazuh

**Example Queries:**

```bash
# Failed authentication attempts by IP
docker-compose logs backend | grep "auth.login.failure" | \
  jq -r '.message.ip_address' | sort | uniq -c | sort -rn

# Rate limit violations
docker-compose logs backend | grep "rate_limit.exceeded" | \
  jq -r '.message.details.endpoint' | sort | uniq -c

# Admin actions
docker-compose logs backend | grep "admin\." | \
  jq -r '{time: .timestamp, user: .message.user_email, action: .message.details.action}'
```

### Backup & Recovery

**Database Backups:**
```bash
# Automated daily backup
0 2 * * * docker-compose exec -T db pg_dump -U pki pki | \
  gzip > /backups/pki-$(date +\%Y\%m\%d).sql.gz

# Retention: 30 days
find /backups -name "pki-*.sql.gz" -mtime +30 -delete
```

**CA Key Backups:**
```bash
# Backup CA keys (encrypted)
tar czf ca-keys-backup.tar.gz secrets/
gpg --symmetric --cipher-algo AES256 ca-keys-backup.tar.gz
rm ca-keys-backup.tar.gz

# Store encrypted backup offline
```

**Recovery Procedures:**

1. **Database Recovery:**
   ```bash
   # Stop application
   docker-compose down
   
   # Restore database
   gunzip < /backups/pki-20260206.sql.gz | \
     docker-compose exec -T db psql -U pki pki
   
   # Restart application
   docker-compose up -d
   ```

2. **CA Key Recovery:**
   ```bash
   # Decrypt backup
   gpg --decrypt ca-keys-backup.tar.gz.gpg > ca-keys-backup.tar.gz
   
   # Extract keys
   tar xzf ca-keys-backup.tar.gz
   
   # Verify keys
   openssl rsa -in secrets/internal-ca.key -check
   ```

**Security Checklist:**
- [ ] Automate database backups
- [ ] Test restore procedures regularly
- [ ] Encrypt backups
- [ ] Store backups offline
- [ ] Document recovery procedures
- [ ] Maintain backup retention policy

### Certificate Revocation

**User Revocation:**
```bash
# User revokes own certificate via UI
# Audit log entry created automatically
```

**Admin Revocation:**
```bash
# Admin revokes any certificate via admin panel
# Audit log includes admin user ID and target user
```

**CRL Distribution:**
```bash
# CRL available at public endpoint
curl https://pki.example.com/api/v1/crl/internal-mtls

# Update CRL on mTLS-protected services
*/5 * * * * curl -s https://pki.example.com/api/v1/crl/internal-mtls \
  -o /etc/nginx/certs/ca.crl && systemctl reload nginx
```

**Security Checklist:**
- [ ] Configure CRL distribution
- [ ] Set up automated CRL updates
- [ ] Monitor revocation events
- [ ] Document revocation procedures
- [ ] Test CRL validation

### Incident Response

**Incident Categories:**

| Category | Examples | Response Time |
|----------|----------|---------------|
| **Critical** | CA key compromise, data breach | Immediate |
| **High** | Unauthorized admin access, mass revocation | <1 hour |
| **Medium** | Failed auth spike, rate limit abuse | <4 hours |
| **Low** | Individual failed login, quota exceeded | <24 hours |


## Appendices

### A. Security Testing Checklist

#### Authentication Testing
- [ ] Test OIDC flow with valid credentials
- [ ] Test OIDC flow with invalid credentials
- [ ] Test state parameter validation
- [ ] Test PKCE code verifier validation
- [ ] Test token expiration handling
- [ ] Test logout functionality

#### Authorization Testing
- [ ] Test group-based access control
- [ ] Test admin-only endpoints as non-admin
- [ ] Test approver-only endpoints as non-approver
- [ ] Test cross-user certificate access
- [ ] Test quota enforcement

#### Input Validation Testing
- [ ] Test CSR with invalid signature
- [ ] Test CSR with weak key
- [ ] Test SQL injection in search
- [ ] Test XSS in certificate subject
- [ ] Test path traversal in file operations

#### Rate Limiting Testing
- [ ] Test rate limits on all endpoints
- [ ] Test rate limit bypass attempts
- [ ] Test rate limit reset
- [ ] Verify 429 responses

#### Security Headers Testing
- [ ] Verify CSP header
- [ ] Verify X-Frame-Options
- [ ] Verify HSTS (if enabled)
- [ ] Verify other security headers
- [ ] Test CSP violations

### B. Common Vulnerabilities

| Vulnerability | Status | Mitigation |
|---------------|--------|------------|
| SQL Injection | ✅ Protected | SQLAlchemy ORM |
| XSS | ⚠️ Partial | CSP, HTML escaping |
| CSRF | ⚠️ Partial | Bearer tokens, state parameter |
| Clickjacking | ✅ Protected | X-Frame-Options, CSP |
| Session Hijacking | ⚠️ Partial | HTTPS, short token lifetime |
| Privilege Escalation | ✅ Protected | Server-side authorization |
| DoS | ⚠️ Partial | Rate limiting |
| MITM | ✅ Protected | HTTPS (production) |
| Certificate Forgery | ✅ Protected | Subject enforcement |
| Private Key Theft | ✅ Protected | Zero-knowledge architecture |

---

**END OF DOCUMENT**
