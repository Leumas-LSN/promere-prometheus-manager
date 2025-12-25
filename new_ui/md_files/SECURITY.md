# Security Enhancements - Promere

This document outlines all security improvements implemented in Promere.

---

## 🔒 Security Features Implemented

### 1. **HTTPS/SSL Encryption**

- **Self-Signed Certificate Generation**: Automatically generated at first startup
- **Certificate Location**: `certs/cert.pem` and `certs/key.pem`
- **Validity**: 365 days (configurable)
- **Protocol**: TLS 1.2+ with SHA256 signatures
- **Subject Alternative Names**: Supports `localhost`, `*.localhost`, and `127.0.0.1`

**Configuration**:
```bash
# In .env file
USE_HTTPS=true
PORT=8443
```

**Access**: https://localhost:8443

⚠️ **Production Note**: For production deployments, replace the self-signed certificate with a valid certificate from a trusted CA (Let's Encrypt, etc.) or use a reverse proxy (nginx/traefik) for SSL termination.

---

### 2. **Password Security (Bcrypt)**

#### Migration System
- **Automatic Migration**: On first startup, plaintext passwords from `.env` are automatically hashed with bcrypt
- **Hash Storage**: `config/password_hashes.json` (permissions: 0600)
- **Algorithm**: bcrypt with salt rounds (cost factor: 12)

#### Password Requirements
- Minimum 8 characters recommended
- Mix of uppercase, lowercase, numbers, and symbols
- Default password (`admin`) **must be changed immediately**

#### How It Works
1. Application reads plaintext passwords from `.env` on first startup
2. Generates bcrypt hashes and stores them in `password_hashes.json`
3. Future authentications use only the hashed versions
4. Original plaintext passwords in `.env` can be removed (but kept for recovery)

**Security Benefit**: Even if an attacker gains access to the hash file, they cannot reverse the passwords.

---

### 3. **Session Security**

#### Hardening Measures
- **HttpOnly Cookies**: Prevents JavaScript access (XSS protection)
- **SameSite=Lax**: CSRF protection
- **Secure Flag**: Cookies only sent over HTTPS
- **Session Timeout**: 2-hour automatic expiration
- **Session Regeneration**: Session ID rotated after successful login (prevents session fixation)

#### Implementation
```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2)
)
```

---

### 4. **Rate Limiting**

#### Protected Endpoints
- **Login Route** (`/login`): 10 attempts per minute per IP
- **Global Limit**: 200 requests per day, 50 per hour per IP

#### Implementation
- Uses `Flask-Limiter` with in-memory storage
- Rate limit violations return HTTP 429 (Too Many Requests)

#### Configuration
```python
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    ...
```

**Security Benefit**: Prevents brute-force password attacks and DoS attempts.

---

### 5. **Input Validation & SSRF Protection**

#### Target Validation
- **Format**: Only accepts `host:port` format
- **Port Range**: 1-65535
- **Character Whitelist**: Alphanumeric, dots, hyphens, colons, underscores

#### URL Validation (Anti-SSRF)
- **Blocked Hosts**:
  - `169.254.169.254` (Cloud metadata services)
  - `127.0.0.1`, `localhost`, `0.0.0.0`
  - Private IP ranges (RFC1918) - optional
- **Allowed Schemes**: Only `http` and `https`

#### Functions
```python
validate_target(target: str) -> bool
validate_url(url: str, allow_private: bool = False) -> bool
sanitize_input(value: str, max_length: int = 1000) -> str
```

**Security Benefit**: Prevents attackers from:
- Scanning internal networks
- Accessing cloud metadata APIs
- Injecting malicious payloads

---

### 6. **CSRF Protection**

#### Implementation
- **Token Generation**: Uses `secrets.token_hex(32)` (64 characters)
- **Timing-Safe Comparison**: Uses `secrets.compare_digest()` to prevent timing attacks
- **Token Storage**: Session-based

#### Usage
All forms include a hidden CSRF token:
```html
<input type="hidden" name="_csrf" value="{{ csrf }}">
```

Server-side validation:
```python
if not check_csrf():
    flash("CSRF invalide. Rechargez la page.", "error")
    return redirect(...)
```

---

### 7. **Security Headers**

#### Headers Applied
```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net unpkg.com; ...
```

#### CSP Details
- **Default**: Only allow resources from same origin
- **Scripts**: Allow inline scripts (required for Alpine.js) and CDN (jsdelivr, tailwindcss.com, unpkg)
- **Styles**: Allow inline styles and CDN (jsdelivr, fonts.googleapis.com)
- **Fonts**: Allow fonts from CDN (jsdelivr, fonts.gstatic.com)
- **Images**: Allow data URIs for inline images
- **Frames**: Prevent embedding in other sites

Full CSP:
```
default-src 'self';
script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdn.tailwindcss.com unpkg.com;
style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com;
font-src 'self' cdn.jsdelivr.net fonts.gstatic.com;
img-src 'self' data:;
connect-src 'self';
frame-ancestors 'self'
```

---

### 8. **Cryptographic Improvements**

#### API Key Hashing
- **Algorithm**: SHA256 (was already implemented)
- **Format**: `pk_<32_random_bytes>`
- **Storage**: Only hash stored, raw key shown once

#### Satellite Agent Checksums
- **Changed**: MD5 → SHA256
- **Purpose**: Detect configuration changes
- **Security Benefit**: MD5 is cryptographically broken; SHA256 prevents collision attacks

---

### 9. **Logging & Auditing**

#### Security Events Logged
- Login attempts (success and failure)
- IP address of login attempts
- CSRF validation failures
- File write/read errors in satellite agent
- Exception tracebacks (for debugging)

#### Log Locations
- **Application Log**: `app.log`
- **Activity Log**: `activity_log.json` (user-facing audit trail)

#### Example Log Entries
```
2025-01-15 10:32:15 [INFO] Login attempt for user 'admin' from 192.168.1.10
2025-01-15 10:32:16 [INFO] Successful login for user 'admin' with role 'admin' from 192.168.1.10
2025-01-15 10:35:22 [WARNING] Failed login attempt for user 'hacker' from 203.0.113.5
```

---

### 10. **Secret Key Management**

#### Automatic Generation
If `SECRET_KEY` in `.env` is missing or < 32 characters:
- Automatically generates a secure 64-character random key
- Logs the key to console (must be added to `.env` manually)
- Uses `secrets.token_hex(32)`

#### Recommendation
Generate a strong key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Add to `.env`:
```bash
SECRET_KEY=your_64_character_random_string_here
```

---

## 🔧 Configuration Guide

### Environment Variables (.env)

```bash
# Admin credentials (will be migrated to bcrypt hashes)
ADMIN_USER=admin
ADMIN_PASS=your_strong_password_here

# Flask secret key (64 characters)
SECRET_KEY=generate_with_python_secrets_module

# HTTPS configuration
USE_HTTPS=true
PORT=8443
HOST=0.0.0.0
```

### First Startup Checklist

1. **Change Default Password**
   - Default `admin` password must be changed immediately
   - Use a strong password (12+ characters)

2. **Generate Secret Key**
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```
   - Add to `.env` file

3. **SSL Certificate**
   - Self-signed cert is auto-generated
   - For production, use a trusted CA certificate

4. **Review Logs**
   - Check `app.log` for any warnings
   - Verify certificate generation succeeded

5. **Test HTTPS**
   - Access https://localhost:8443
   - Accept self-signed certificate warning (browser)

---

## 🚨 Security Recommendations

### Production Deployment

1. **Use a Reverse Proxy**
   - nginx or traefik in front of the application
   - Let the proxy handle SSL termination with valid certificates
   - Example nginx config:
     ```nginx
     server {
         listen 443 ssl http2;
         server_name promere.example.com;

         ssl_certificate /etc/letsencrypt/live/promere.example.com/fullchain.pem;
         ssl_certificate_key /etc/letsencrypt/live/promere.example.com/privkey.pem;

         location / {
             proxy_pass http://promere:8443;
             proxy_set_header Host $host;
             proxy_set_header X-Real-IP $remote_addr;
         }
     }
     ```

2. **Firewall Configuration**
   - Only expose necessary ports (443 for HTTPS)
   - Block direct access to port 8443 from external networks

3. **Regular Updates**
   - Keep dependencies updated: `pip install --upgrade -r requirements.txt`
   - Monitor security advisories for Flask, bcrypt, cryptography

4. **Backup Credentials**
   - Store `config/password_hashes.json` securely
   - Keep `.env` in a secrets manager (HashiCorp Vault, AWS Secrets Manager)

5. **Enable HSTS Preloading**
   - Submit domain to HSTS preload list
   - Add `preload` directive to HSTS header

6. **Monitor Logs**
   - Set up log aggregation (ELK stack, Grafana Loki)
   - Alert on failed login attempts
   - Track authentication anomalies

---

## 🛡️ Threat Model

### Mitigated Threats

| Threat | Mitigation |
|--------|-----------|
| **Password Cracking** | Bcrypt hashing with high cost factor |
| **Man-in-the-Middle** | HTTPS/TLS encryption |
| **Session Hijacking** | HttpOnly, Secure, SameSite cookies |
| **Session Fixation** | Session ID regeneration after login |
| **Brute Force** | Rate limiting (10 attempts/min) |
| **CSRF** | Token-based protection with timing-safe comparison |
| **XSS** | CSP, HttpOnly cookies, input sanitization |
| **Clickjacking** | X-Frame-Options: SAMEORIGIN |
| **SSRF** | URL validation, private IP blocking |
| **Injection Attacks** | Input validation, sanitization |
| **Timing Attacks** | secrets.compare_digest() for token comparison |

### Remaining Risks

- **Self-Signed Certificates**: Browser warnings may lead to user trust issues
  - **Mitigation**: Use trusted CA certificates in production

- **In-Memory Rate Limiting**: Resets on container restart
  - **Mitigation**: Use Redis for persistent rate limiting

- **No Account Lockout**: Failed logins don't lock accounts
  - **Mitigation**: Implement progressive delays or lockout after N failures

---

## 📋 Compliance

### Standards Met

- **OWASP Top 10 (2021)**
  - A01: Broken Access Control ✅ (RBAC)
  - A02: Cryptographic Failures ✅ (bcrypt, TLS, SHA256)
  - A03: Injection ✅ (Input validation)
  - A04: Insecure Design ✅ (Security by design)
  - A05: Security Misconfiguration ✅ (Security headers, secure defaults)
  - A06: Vulnerable Components ✅ (Updated dependencies)
  - A07: Authentication Failures ✅ (bcrypt, rate limiting)
  - A08: Software & Data Integrity ✅ (SHA256 checksums)
  - A09: Logging Failures ✅ (Comprehensive logging)
  - A10: SSRF ✅ (URL validation)

---

## 📞 Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to: [your-security-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

---

## 📝 Changelog

### 2025-01-15 - Security Hardening Release

- ✅ Added bcrypt password hashing
- ✅ Implemented HTTPS with auto-generated SSL certificates
- ✅ Added rate limiting (Flask-Limiter)
- ✅ Enhanced session security (rotation, timeout)
- ✅ Implemented input validation & SSRF protection
- ✅ Added comprehensive security headers (CSP, HSTS, etc.)
- ✅ Improved CSRF protection (timing-safe comparison)
- ✅ Replaced MD5 with SHA256 in satellite agent
- ✅ Enhanced logging & exception handling
- ✅ Auto-generated SECRET_KEY if missing

---

**Last Updated**: 2025-01-15
**Version**: 2.0.0-security
**Author**: Promere Security Team
