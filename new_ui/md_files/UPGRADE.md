# Upgrade Guide - Promere Security Update

This guide helps you migrate from the previous version to the new security-hardened version.

---

## 🔄 Breaking Changes

### 1. **HTTPS is Now Enforced**
- **Old**: HTTP on port 8091
- **New**: HTTPS on port 8443 (HTTP port still available but deprecated)

### 2. **Session Cookies Require HTTPS**
- `SESSION_COOKIE_SECURE=True` is now enforced
- Sessions won't work over HTTP

### 3. **Password Storage**
- **Old**: Plaintext passwords in `.env` compared directly
- **New**: Bcrypt hashes stored in `config/password_hashes.json`

### 4. **SECRET_KEY Requirement**
- Must be 32+ characters
- Auto-generated if missing (but should be set manually)

---

## 📦 Migration Steps

### Step 1: Backup Your Data

```bash
# Backup configuration files
cp .env .env.backup
cp config.json config.json.backup
cp -r config/ config.backup/

# Backup activity logs
cp activity_log.json activity_log.json.backup
```

### Step 2: Update Dependencies

```bash
# Stop the application
docker-compose down

# Rebuild with new dependencies
docker-compose build --no-cache

# Or if running locally:
pip install -r requirements.txt
```

### Step 3: Update .env File

Add the new variables to your `.env` file:

```bash
# Generate a strong SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"

# Add to .env
SECRET_KEY=<your_generated_key_here>

# HTTPS configuration
USE_HTTPS=true
PORT=8443
HOST=0.0.0.0
```

### Step 4: Start Application (Password Migration)

```bash
docker-compose up -d
```

**What happens on first startup**:
1. Application reads plaintext passwords from `.env`
2. Generates bcrypt hashes
3. Saves hashes to `config/password_hashes.json`
4. Logs a warning to change passwords
5. Generates SSL certificate if not present

**Check the logs**:
```bash
docker-compose logs -f prototype
```

You should see:
```
Migrating password for user 'Leumas' (admin)
SECURITY: Plaintext passwords migrated to bcrypt hashes.
RECOMMENDATION: Remove plaintext passwords from .env file!
Generating self-signed SSL certificate...
SSL certificate generated successfully
Starting application on HTTPS (port 8443)...
```

### Step 5: Verify Certificate Generation

```bash
# Check if certificates were created
ls -la certs/
# Should show: cert.pem, key.pem
```

### Step 6: Access Application via HTTPS

1. Open browser: https://localhost:8443
2. Accept the self-signed certificate warning
   - Chrome: Click "Advanced" → "Proceed to localhost (unsafe)"
   - Firefox: Click "Advanced" → "Accept the Risk and Continue"

### Step 7: Change Default Password

1. Login with your current credentials
2. Go to Team/Profile settings
3. Change password immediately if using default `admin`

### Step 8: (Optional) Remove Plaintext Passwords

After successful migration, you can remove plaintext passwords from `.env`:

```bash
# Keep only usernames, remove passwords
ADMIN_USER=Leumas
# ADMIN_PASS=admin  <-- Comment out or remove
```

⚠️ **Warning**: Keep a backup of `.env` with passwords in case you need to regenerate hashes!

---

## 🔧 Configuration Changes

### docker-compose.yml Updates

**Old**:
```yaml
ports:
  - "8091:8091"
```

**New**:
```yaml
ports:
  - "8443:8443"  # HTTPS (primary)
  - "8091:8091"  # HTTP (legacy, can be removed)

volumes:
  - ./certs:/app/certs          # SSL certificates
  - ./config:/app/config        # Password hashes, API keys
```

### Dockerfile Changes

**Old**:
```dockerfile
RUN pip install flask requests python-dotenv pyyaml
```

**New**:
```dockerfile
COPY requirements.txt /app/
RUN pip install -r requirements.txt
```

---

## 🐛 Troubleshooting

### Issue: "Connection Refused" on Port 8443

**Cause**: Application failed to start or SSL setup failed

**Solution**:
```bash
# Check logs
docker-compose logs prototype

# Check if container is running
docker ps

# Rebuild if necessary
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Issue: "Invalid credentials" After Migration

**Cause**: Password hash mismatch

**Solution**:
```bash
# Remove hash file and restart (forces re-migration)
rm config/password_hashes.json
docker-compose restart
```

### Issue: Browser Shows "Your connection is not private"

**Cause**: Self-signed certificate (expected behavior)

**Solution**:
- Click "Advanced" and proceed (development)
- Use a valid CA certificate (production)
- Or use a reverse proxy with Let's Encrypt

### Issue: Sessions Not Persisting

**Cause**: SECRET_KEY changed between restarts

**Solution**:
```bash
# Ensure SECRET_KEY is set in .env and doesn't change
# If auto-generated, copy it from logs to .env

# Check logs for:
# "Generated SECRET_KEY: <key>"
# Copy that key to .env
```

### Issue: Rate Limiting Blocking Legitimate Users

**Cause**: Too aggressive rate limits

**Solution**:
Edit `app.py`:
```python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],  # Increase limits
    storage_uri="memory://"
)
```

---

## 🔐 Security Checklist

After upgrade, verify:

- [ ] HTTPS is working (https://localhost:8443)
- [ ] Certificate was generated (`certs/cert.pem` exists)
- [ ] Password hashes were created (`config/password_hashes.json` exists)
- [ ] Can login successfully
- [ ] Session persists across page refreshes
- [ ] Default password was changed
- [ ] SECRET_KEY is set in `.env` (32+ characters)
- [ ] Logs show no errors (`docker-compose logs`)
- [ ] Rate limiting works (try 11 failed logins in 1 minute)
- [ ] CSRF protection works (test with curl without token)

---

## 📊 Feature Comparison

| Feature | Old Version | New Version |
|---------|-------------|-------------|
| **Transport** | HTTP only | HTTPS (TLS 1.2+) |
| **Port** | 8091 | 8443 (8091 legacy) |
| **Passwords** | Plaintext | Bcrypt hashed |
| **Session Security** | Basic | HttpOnly, Secure, SameSite |
| **Rate Limiting** | None | 10 login attempts/min |
| **CSRF Protection** | Basic | Timing-safe comparison |
| **Input Validation** | Minimal | Comprehensive + SSRF protection |
| **Security Headers** | Basic | CSP, HSTS, X-Frame-Options |
| **Logging** | Basic | Security events + IP tracking |
| **Exception Handling** | Silent failures | Comprehensive logging |
| **Checksums** | MD5 | SHA256 |

---

## 🚀 Next Steps

1. **Production Deployment**:
   - Set up reverse proxy (nginx/traefik)
   - Obtain trusted SSL certificate (Let's Encrypt)
   - Configure firewall rules

2. **Monitoring**:
   - Set up log aggregation
   - Create alerts for failed logins
   - Monitor rate limit hits

3. **Backup**:
   - Automate backup of `config/password_hashes.json`
   - Backup SSL certificates
   - Version control `.env` (encrypted)

---

## 📞 Support

If you encounter issues:

1. Check logs: `docker-compose logs -f`
2. Review `SECURITY.md` for configuration details
3. Open an issue on GitHub with:
   - Error messages
   - Log output
   - Steps to reproduce

---

**Last Updated**: 2025-01-15
**Migration Version**: 1.x → 2.0.0
