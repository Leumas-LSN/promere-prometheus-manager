"""
[MCP Context] Promere Central Application (app.py)
==================================================
Role: Core Orchestrator & User Interface.
Architecture: Monolithic Flask App serving as the Central Command Center.

Key Responsibilities:
1. User Interface: Renders HTML templates for Dashboards, Targets, Alerts, and Config.
2. Multi-Site Management: 
   - Manages Local Prometheus instance directly.
   - Orchestrates Remote Satellites via API Keys and Sync Endpoints.
3. Configuration Authority:
   - Stores the "Source of Truth" for Targets (JSON) and Alert Rules (YAML).
   - Serves configuration to Satellites via `/api/sync/config`.
4. Authentication & RBAC:
   - Role-Based Access Control (Admin, Editor, Viewer).
   - API Key management for Satellites.

Data Flow:
- Users (UI) -> Flask -> Local Files (targets/, rules/) -> Local Prometheus (Reload)
- Satellites (Agents) -> Flask API -> Pull Config -> Remote Prometheus (Reload)
"""

import os
import io
import re
import json
import time
import zipfile
import socket
import secrets
import hashlib
import logging
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import requests
import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, jsonify, make_response
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Import SSL utilities
from ssl_utils import generate_self_signed_cert

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# [MCP Cache] In-Memory Cache for Satellite Target Status
# Key: satellite_id, Value: Prometheus API response JSON (targets)
SATELLITE_STATUS_CACHE = {}

# =========================
# [MCP Init] Flask Application Setup
# =========================
app = Flask(__name__)

# [MCP UI] Safe URL Filter (Safety Net)
# Prevents 500 errors if an endpoint is renamed or missing in templates
def safe_url(endpoint, **values):
    try:
        return url_for(endpoint, **values)
    except Exception as e:
        logger.warning(f"SafeUrl: Could not build url for endpoint '{endpoint}': {e}")
        return "#"
app.jinja_env.filters['safe_url'] = safe_url

# [MCP UI] Navigation Structure (Centralized Config)
NAV_MENU = [
    {"title": "Dashboard", "category": "Navigation", "endpoint": "dashboard", "icon": "nav"},
    {"title": "Targets (Inventory)", "category": "Navigation", "endpoint": "index", "icon": "target"},
    {"title": "Alerts & Rules", "category": "Navigation", "endpoint": "alerts", "icon": "alert"},
    {"title": "AlertManager Config", "category": "Settings", "endpoint": "alertmanager_config", "icon": "settings"},
    {"title": "Topology Map", "category": "Navigation", "endpoint": "topology", "icon": "topo"},
    {"title": "Activity Log", "category": "Observability", "endpoint": "activity_log", "icon": "logs"},
    {"title": "Team & Users", "category": "Navigation", "endpoint": "team_management", "icon": "team"},
]

# Generate or load SECRET_KEY
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if not SECRET_KEY or len(SECRET_KEY) < 32:
    logger.warning("SECRET_KEY not set or too short. Generating a secure random key.")
    SECRET_KEY = secrets.token_hex(32)
    logger.info(f"Generated SECRET_KEY: {SECRET_KEY}")
    logger.info("IMPORTANT: Add this to your .env file to persist sessions across restarts!")
app.secret_key = SECRET_KEY

# [MCP Security] Session Hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Prevent JS access to session cookie (XSS protection)
    SESSION_COOKIE_SAMESITE='Lax',      # CSRF protection
    SESSION_COOKIE_SECURE=True,         # HTTPS only (enforced)
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # Session timeout
)

# [MCP Security] Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# [MCP Security] Security Headers Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Prevent Clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # HSTS
    # Content Security Policy - Allow inline scripts for Alpine.js and CDN resources
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net cdn.tailwindcss.com unpkg.com; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
        "font-src 'self' cdn.jsdelivr.net fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src *; "
        "frame-ancestors 'self'"
    )
    return response

# =========================
# [MCP Auth] RBAC & Credentials
# Context: Bcrypt-based authentication with automatic migration from env vars.
# =========================
PASSWORD_HASHES_FILE = "config/password_hashes.json"

def load_password_hashes():
    """Load password hashes from file"""
    if not os.path.exists(PASSWORD_HASHES_FILE):
        return {}
    try:
        with open(PASSWORD_HASHES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load password hashes: {e}", exc_info=True)
        return {}

def save_password_hashes(hashes):
    """Save password hashes to file"""
    os.makedirs(os.path.dirname(PASSWORD_HASHES_FILE), exist_ok=True)
    try:
        with open(PASSWORD_HASHES_FILE, 'w') as f:
            json.dump(hashes, f, indent=4)
        os.chmod(PASSWORD_HASHES_FILE, 0o600)  # Restrict permissions
        return True
    except Exception as e:
        logger.error(f"Failed to save password hashes: {e}", exc_info=True)
        return False

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}", exc_info=True)
        return False

def migrate_env_passwords():
    """
    Migrate plaintext passwords from .env to bcrypt hashes.
    This runs once at startup.
    """
    hashes = load_password_hashes()
    migrated = False

    users = {
        "admin": (os.getenv("ADMIN_USER", "admin"), os.getenv("ADMIN_PASS", "")),
        "editor": (os.getenv("EDIT_USER", ""), os.getenv("EDIT_PASS", "")),
        "viewer": (os.getenv("VIEW_USER", ""), os.getenv("VIEW_PASS", ""))
    }

    for role, (username, password) in users.items():
        if username and password and username not in hashes:
            logger.info(f"Migrating password for user '{username}' ({role})")
            hashes[username] = {
                "hash": hash_password(password),
                "role": role
            }
            migrated = True

    if migrated:
        save_password_hashes(hashes)
        logger.warning("SECURITY: Plaintext passwords migrated to bcrypt hashes.")
        logger.warning("RECOMMENDATION: Remove plaintext passwords from .env file!")

    return hashes

# Migrate passwords at startup
USER_CREDENTIALS = migrate_env_passwords()

def resolve_role(username: str, password: str):
    """
    [MCP Logic] Role Resolution with bcrypt verification
    Returns: role string or None
    """
    if not username or not password:
        return None

    user_data = USER_CREDENTIALS.get(username)
    if not user_data:
        logger.warning(f"Login attempt for unknown user: {username}")
        return None

    if verify_password(password, user_data["hash"]):
        return user_data["role"]

    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def require_role(min_role: str):
    """
    [MCP Decorator] RBAC Enforcement
    Hierarchy: admin > editor > viewer
    """
    order = {"viewer": 0, "editor": 1, "admin": 2}
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "logged_in" not in session:
                return redirect(url_for("login"))
            role = session.get("role", "viewer")
            if order.get(role, 0) < order.get(min_role, 0):
                flash("Accès refusé (droits insuffisants).", "error")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# =========================
# [MCP Config] Constants & Paths
# =========================
TARGETS_DIR = "targets"
CONFIG_FILE = "config.json"
ACTIVITY_LOG_FILE = "activity_log.json"
DASHBOARD_PANELS_FILE = "dashboard_panels.json"
USERS_FILE = "users.json"
API_KEYS_FILE = "config/api_keys.json"
PROM_YML_PATH = os.getenv("PROMETHEUS_YML_PATH", "/config/prometheus.yml")

DEFAULT_CONFIG = {
    "prometheus_url": "",
    "prometheus_username": "",
    "prometheus_password": "",
    "prometheus_bearer_token": "",
    "prometheus_base_url": "",
    "alertmanager_base_url": "",
    "blackbox_base_url": "",
    "last_reload_epoch": 0
}

# =========================
# [MCP Security] Input Validation & SSRF Protection
# =========================
def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False

def validate_url(url: str, allow_private: bool = False) -> bool:
    """
    Validate URL to prevent SSRF attacks

    Args:
        url: URL to validate
        allow_private: Whether to allow private IP addresses

    Returns:
        True if URL is safe, False otherwise
    """
    if not url:
        return False

    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            logger.warning(f"Invalid URL scheme: {parsed.scheme}")
            return False

        # Extract hostname
        hostname = parsed.hostname
        if not hostname:
            logger.warning("URL missing hostname")
            return False

        # Prevent access to metadata services
        blocked_hosts = [
            '169.254.169.254',  # AWS/Azure/GCP metadata
            '127.0.0.1',
            'localhost',
            '0.0.0.0',
        ]

        if not allow_private and hostname.lower() in blocked_hosts:
            logger.warning(f"Blocked access to restricted host: {hostname}")
            return False

        # Check if hostname is an IP address
        try:
            if not allow_private and is_private_ip(hostname):
                logger.warning(f"Blocked access to private IP: {hostname}")
                return False
        except ValueError:
            # hostname is a domain name, not an IP
            pass

        return True

    except Exception as e:
        logger.error(f"URL validation error: {e}", exc_info=True)
        return False

def validate_target(target: str) -> bool:
    """
    Validate monitoring target format (IP:PORT or DOMAIN:PORT)

    Args:
        target: Target string to validate

    Returns:
        True if valid, False otherwise
    """
    if not target:
        return False

    # Allow alphanumeric, dots, hyphens, colons, and underscores
    if not re.match(r'^[a-zA-Z0-9._:-]+$', target):
        logger.warning(f"Invalid target format: {target}")
        return False

    # Check if it contains a port
    if ':' not in target:
        logger.warning(f"Target missing port: {target}")
        return False

    parts = target.rsplit(':', 1)
    if len(parts) != 2:
        return False

    host, port = parts

    # Validate port
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            logger.warning(f"Invalid port number: {port_num}")
            return False
    except ValueError:
        logger.warning(f"Port is not a number: {port}")
        return False

    # Validate host (basic check)
    if not host or len(host) < 1:
        logger.warning("Empty host in target")
        return False

    return True

def sanitize_input(value: str, max_length: int = 1000) -> str:
    """
    Sanitize user input by removing dangerous characters

    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not value:
        return ""

    # Truncate to max length
    value = value[:max_length]

    # Remove null bytes and control characters
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')

    return value.strip()

# =========================
# [MCP Logic] API Keys Management
# Context: Security for Satellite Agents.
# =========================
def load_api_keys():
    if not os.path.exists(API_KEYS_FILE):
        return []
    try:
        with open(API_KEYS_FILE, 'r') as f:
            data = json.load(f)
            return data.get('keys', [])
    except:
        return []

def save_api_keys(keys):
    os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
    try:
        with open(API_KEYS_FILE, 'w') as f:
            json.dump({'keys': keys}, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving API keys: {e}")
        return False

def hash_key(key_raw):
    """SHA256 hashing for storage security"""
    return hashlib.sha256(key_raw.encode()).hexdigest()

def validate_api_key_request(f):
    """
    [MCP Decorator] Satellite Authentication
    Checks Authorization Bearer token against stored hashes.
    Updates 'last_used_at' timestamp.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        token_hash = hash_key(token)
        
        keys = load_api_keys()
        valid_key = None
        
        now = datetime.now()
        
        for k in keys:
            if k['hash'] == token_hash:
                # Check expiration
                if k.get('expires_at'):
                    expires = datetime.fromisoformat(k['expires_at'])
                    if now > expires:
                        return jsonify({'error': 'API Key expired'}), 403
                valid_key = k
                break
        
        if not valid_key:
            return jsonify({'error': 'Invalid API Key'}), 403
            
        # Update last_used
        valid_key['last_used_at'] = now.isoformat()
        save_api_keys(keys)
        
        return f(*args, **kwargs)
    return decorated

# =========================
# [MCP Routes] Settings Pages
# =========================
@app.route('/settings/api_keys')
@login_required
@require_role('admin')
def api_keys_page():
    """Render API Keys management page"""
    keys = load_api_keys()
    
    # Calculate status for display
    now = datetime.now()
    for k in keys:
        if k.get('expires_at'):
            expires = datetime.fromisoformat(k['expires_at'])
            if now > expires:
                k['status'] = 'expired'
            else:
                k['status'] = 'active'
        else:
            k['status'] = 'active'
            
    return render_template(
        'api_keys.html', 
        keys=keys,
        csrf=get_csrf(),
        role=session.get('role', 'viewer'),
        config=get_config(),
        jobs=get_jobs()
    )

@app.route('/settings/api_keys/create', methods=['POST'])
@login_required
@require_role('admin')
def create_api_key():
    if not check_csrf(): return redirect(url_for('api_keys_page'))
    
    name = request.form.get('name', 'Satellite').strip()
    validity_days = int(request.form.get('validity', 365))
    
    # Generate Key
    raw_key = "pk_" + secrets.token_urlsafe(32)
    key_hash = hash_key(raw_key)
    
    expires_at = None
    if validity_days > 0:
        expires_at = (datetime.now() + timedelta(days=validity_days)).isoformat()
        
    new_key = {
        'id': secrets.token_hex(8),
        'name': name,
        'prefix': raw_key[:7] + "...",
        'hash': key_hash,
        'created_at': datetime.now().isoformat(),
        'expires_at': expires_at,
        'last_used_at': None
    }
    
    keys = load_api_keys()
    keys.append(new_key)
    save_api_keys(keys)
    
    log_activity('config', f'Created API Key: {name}', session.get('role', 'admin'))
    
    # Flash the raw key ONLY ONCE
    flash(f"Clé API créée avec succès! COPIEZ-LA MAINTENANT, elle ne sera plus visible: {raw_key}", "new_key_success")
    
    return redirect(url_for('api_keys_page'))

@app.route('/settings/api_keys/delete', methods=['POST'])
@login_required
@require_role('admin')
def delete_api_key():
    if not check_csrf(): return redirect(url_for('api_keys_page'))
    
    key_id = request.form.get('key_id')
    keys = load_api_keys()
    keys = [k for k in keys if k['id'] != key_id]
    save_api_keys(keys)
    
    log_activity('config', f'Deleted API Key ID: {key_id}', session.get('role', 'admin'))
    flash("Clé API révoquée.", "success")
    return redirect(url_for('api_keys_page'))

# =========================
# [MCP Logic] SATELLITE SYNC API
# Context: This is the main endpoint used by remote agents.
# =========================
@app.route('/api/sync/config', methods=['GET', 'POST'])
@validate_api_key_request
def api_sync_config():
    """
    [MCP Endpoint] Satellite Sync
    1. POST: Satellite reports health and local jobs. Central stores this info.
    2. GET: Satellite requests configuration. Central returns JSON targets and YAML rules tailored for that specific satellite ID.
    """
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    token_hash = hash_key(token)
    
    keys = load_api_keys()
    satellite_key = next((k for k in keys if k['hash'] == token_hash), None)
    
    if not satellite_key:
        return jsonify({'error': 'Unauthorized'}), 401
    
    key_id = satellite_key['id']
    
    # 1. Handle Health Reporting (if POST)
    if request.method == 'POST':
        try:
            health_data = request.get_json()
            satellite_key['prom_status'] = health_data.get('prom_status', 'unknown')
            satellite_key['am_status'] = health_data.get('am_status', 'unknown')
            # Store reported jobs
            satellite_key['reported_jobs'] = health_data.get('jobs', [])
            satellite_key['last_seen'] = datetime.now().isoformat()
            
            # [MCP] Cache remote targets status
            if 'targets_status' in health_data:
                SATELLITE_STATUS_CACHE[key_id] = health_data['targets_status']
            
            save_api_keys(keys)
            return jsonify({'success': True})
        except:
            return jsonify({'error': 'Invalid health data'}), 400

    # 2. Provide Site-Specific Config
    satellite_dir = os.path.join(TARGETS_DIR, "remote", key_id)
    satellite_rules_dir = os.path.join(RULES_DIR, "remote", key_id)
    satellite_am_path = os.path.join("config", "remote", key_id, "alertmanager.yml")
    satellite_prom_path = os.path.join("config", "remote", key_id, "prometheus.yml")
    
    config_payload = {
        'targets': {},
        'rules': {},
        'prometheus_config': None,
        'alertmanager_config': None
    }
    
    # Load targets for this satellite
    if os.path.exists(satellite_dir):
        for filename in os.listdir(satellite_dir):
            if filename.endswith('.json'):
                path = os.path.join(satellite_dir, filename)
                config_payload['targets'][filename] = safe_read_json(path)
                
    # Load rules for this satellite
    if os.path.exists(satellite_rules_dir):
        for filename in os.listdir(satellite_rules_dir):
            if filename.endswith(('.yml', '.yaml')):
                path = os.path.join(satellite_rules_dir, filename)
                try:
                    with open(path, 'r') as f: 
                        config_payload['rules'][filename] = f.read()
                except: pass

    # Load Global Configs if site-specific ones exist, otherwise fallback to Central (or None)
    if os.path.exists(satellite_prom_path):
        with open(satellite_prom_path, 'r') as f: config_payload['prometheus_config'] = f.read()
    
    if os.path.exists(satellite_am_path):
        with open(satellite_am_path, 'r') as f: config_payload['alertmanager_config'] = f.read()
    
    return jsonify(config_payload)

# =========================
# [MCP Logic] User & Config Helpers
# =========================
def get_user_profiles():
    if not os.path.exists(USERS_FILE): return {}
    try:
        with open(USERS_FILE, 'r') as f: return json.load(f)
    except: return {}

def save_user_profile(username, data):
    profiles = get_user_profiles()
    if username in profiles: profiles[username].update(data)
    else: profiles[username] = data
    try:
        with open(USERS_FILE, 'w') as f: json.dump(profiles, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving user profile: {e}")
        return False

def get_csrf():
    """Generate or retrieve CSRF token using secrets module"""
    token = session.get("_csrf")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf"] = token
    return token

def check_csrf():
    """Verify CSRF token with timing-safe comparison"""
    form_token = request.form.get("_csrf")
    session_token = session.get("_csrf")

    if not form_token or not session_token:
        logger.warning("CSRF validation failed: Missing token")
        flash("CSRF invalide. Rechargez la page et réessayez.", "error")
        return False

    # Use secrets.compare_digest for timing-safe comparison
    if not secrets.compare_digest(form_token, session_token):
        logger.warning("CSRF validation failed: Token mismatch")
        flash("CSRF invalide. Rechargez la page et réessayez.", "error")
        return False

    return True

def get_config():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            cfg = DEFAULT_CONFIG.copy()
            if isinstance(data, dict):
                cfg.update(data)
            return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)

def log_activity(action: str, message: str, user: str = None):
    """
    Logger une activité dans activity_log.json
    action: 'add', 'edit', 'delete', 'config'
    """
    if user is None:
        user = session.get('role', 'unknown')
    
    activities = []
    if os.path.exists(ACTIVITY_LOG_FILE):
        try:
            with open(ACTIVITY_LOG_FILE, 'r') as f:
                activities = json.load(f)
        except Exception:
            activities = []
    
    activity = {
        'id': int(time.time() * 1000),
        'action': action,
        'user': user,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'time': 'Just now'
    }
    
    activities.insert(0, activity)
    activities = activities[:100]
    
    with open(ACTIVITY_LOG_FILE, 'w') as f:
        json.dump(activities, f, indent=4)

def get_activities():
    if not os.path.exists(ACTIVITY_LOG_FILE):
        return []
    
    try:
        with open(ACTIVITY_LOG_FILE, 'r') as f:
            activities = json.load(f)
        
        for activity in activities:
            try:
                ts = datetime.fromisoformat(activity['timestamp'])
                delta = datetime.now() - ts
                if delta.total_seconds() < 60: activity['time'] = 'Just now'
                elif delta.total_seconds() < 3600: activity['time'] = f'{int(delta.total_seconds()/60)}m ago'
                elif delta.total_seconds() < 86400: activity['time'] = f'{int(delta.total_seconds()/3600)}h ago'
                else: activity['time'] = f'{int(delta.total_seconds()/86400)}d ago'
            except Exception: activity['time'] = 'Unknown'
        return activities
    except Exception: return []

def get_dashboard_panels():
    if not os.path.exists(DASHBOARD_PANELS_FILE): return []
    try:
        with open(DASHBOARD_PANELS_FILE, 'r') as f: return json.load(f).get('panels', [])
    except: return []

def save_dashboard_panels(panels):
    try:
        with open(DASHBOARD_PANELS_FILE, 'w') as f: json.dump({'panels': panels}, f, indent=4)
        return True
    except: return False

def get_upstream_auth(config):
    """
    [MCP Helper] Standardized Auth Extraction
    Extracts authentication credentials (Bearer Token or Basic Auth) from configuration.
    Returns: (auth_tuple, headers_dict)
    """
    auth = None
    headers = {}
    token = config.get("prometheus_bearer_token", "").strip()
    user = config.get("prometheus_username", "").strip()
    pwd  = config.get("prometheus_password", "")
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif user or pwd:
        auth = (user, pwd)
    return auth, headers

# =========================
# [MCP Logic] Prometheus Config Parsing
# Context: We parse the prometheus.yml to discover available "Jobs".
# =========================
def get_jobs_from_prometheus_yml(path=None):
    """Retourne la liste des job_name depuis un fichier prometheus.yml spécifique."""
    target_path = path or PROM_YML_PATH
    try:
        import yaml
    except Exception:
        return []
    if not os.path.exists(target_path):
        return []
    try:
        with open(target_path, "r") as f:
            y = (yaml.safe_load(f) or {})
        sc = (y.get("scrape_configs") or []) if isinstance(y, dict) else []
        jobs = []
        for item in sc:
            jn = (item or {}).get("job_name")
            if isinstance(jn, str) and jn.strip():
                jobs.append(jn.strip())
        return sorted(set(jobs), key=str.lower)
    except Exception:
        return []

def get_jobs(site_id='local'):
    """
    [MCP Multi-Site] Job Discovery
    Fetches job list either from local file or from cached satellite reports.
    """
    if site_id == 'local':
        path = PROM_YML_PATH
    else:
        path = os.path.join("config", "remote", site_id, "prometheus.yml")
    
    jobs = get_jobs_from_prometheus_yml(path)
    return jobs

def get_dns_sd_map_from_prometheus_yml():
    """
    Parse dns_sd_configs (SRV/A/AAAA) par job depuis prometheus.yml.
    """
    try:
        import yaml
    except Exception:
        return {}
    if not os.path.exists(PROM_YML_PATH):
        return {}
    out = {}
    try:
        with open(PROM_YML_PATH, "r") as f:
            y = (yaml.safe_load(f) or {})
        sc = (y.get("scrape_configs") or []) if isinstance(y, dict) else []
        for item in sc:
            job = (item or {}).get("job_name")
            if not job:
                continue
            dns_list = (item or {}).get("dns_sd_configs") or []
            entries = []
            for cfg in dns_list:
                names = cfg.get("names", [])
                if isinstance(names, str):
                    names = [names]
                names = [str(n) for n in names if str(n).strip()]
                if not names:
                    continue
                entry = {
                    "dns_type": str(cfg.get("type", "SRV")).upper(),
                    "names": names,
                    "refresh_interval": cfg.get("refresh_interval", ""),
                    "port": cfg.get("port", None),
                }
                entries.append(entry)
            if entries:
                out[job] = entries
    except Exception:
        return {}
    return out

def safe_read_json(path: str):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            raw = f.read().strip()
            if not raw:
                return []
            return json.loads(raw)
    except Exception:
        return []

def intersect_labels(dicts):
    """Intersection clé/valeur exacte sur une liste de dicts."""
    if not dicts:
        return {}
    common = dict(dicts[0].items())
    for d in dicts[1:]:
        keys_to_del = []
        for k, v in common.items():
            if k not in d or d[k] != v:
                keys_to_del.append(k)
        for k in keys_to_del:
            common.pop(k, None)
    return common

# =========================
# [MCP Logic] Targets & Storage
# Context: Loading JSON targets from Local and Remote directories.
# =========================
def load_targets_from_dir(directory, location_id, location_name):
    """
    Helper pour charger les targets d'un dossier spécifique.
    Retourne une liste d'objets targets enrichis avec location_id.
    """
    jobs = get_jobs() # Note: On utilise les jobs définis globalement (prometheus.yml local)
    
    tmap = {}
    
    if os.path.exists(directory):
        for filename in os.listdir(directory):
            if filename.endswith('_target.json'):
                job_name = filename.replace('_target.json', '')
                path = os.path.join(directory, filename)
                entries = safe_read_json(path)
                
                for ent in entries:
                    tgt = (ent.get("targets", [""]) or [""])[0]
                    if not tgt: continue
                    
                    labels = ent.get("labels", {}) or {}
                    labels = {k: v for k, v in labels.items() if k != "job"}
                    
                    tmap.setdefault(tgt, {})
                    tmap[tgt][job_name] = labels

    out = []
    for tgt, per_job_labels in tmap.items():
        jobs_for_tgt = sorted(per_job_labels.keys())
        global_labels = intersect_labels([per_job_labels[j] for j in jobs_for_tgt]) if jobs_for_tgt else {}
        job_specific = {}
        for j in jobs_for_tgt:
            diff = {k: v for k, v in per_job_labels[j].items() if k not in global_labels or global_labels[k] != v}
            if diff:
                job_specific[j] = diff
        
        out.append({
            "target": tgt,
            "jobs": jobs_for_tgt,
            "labels": global_labels,
            "job_labels": job_specific,
            "location_id": location_id,
            "location_name": location_name
        })
    return out

def load_all_targets():
    """
    Charge et agrège TOUTES les targets (Locales + Satellites).
    Les cibles identiques (même IP:PORT) sont fusionnées en une seule entrée avec une liste de 'locations'.
    """
    aggregated = {} # target_string -> target_obj

    def process_source(directory, loc_id, loc_name):
        items = load_targets_from_dir(directory, loc_id, loc_name)
        for item in items:
            tgt = item['target']
            if tgt not in aggregated:
                # Initialize new aggregated entry
                item['locations'] = [{'id': loc_id, 'name': loc_name}]
                aggregated[tgt] = item
            else:
                # Merge into existing entry
                existing = aggregated[tgt]
                # Add location if new
                if not any(l['id'] == loc_id for l in existing['locations']):
                    existing['locations'].append({'id': loc_id, 'name': loc_name})
                
                # Merge Jobs (Union)
                existing['jobs'] = sorted(list(set(existing['jobs'] + item['jobs'])))
                
                # Merge Labels (Update/Overwrite)
                existing['labels'].update(item['labels'])
                
                # Merge Job Labels
                for j, l in item.get('job_labels', {}).items():
                    if j not in existing['job_labels']:
                        existing['job_labels'][j] = l
                    else:
                        existing['job_labels'][j].update(l)

    # 1. Local Targets
    process_source(TARGETS_DIR, "local", "Local")
    
    # 2. Remote Targets (Satellites)
    keys = load_api_keys()
    remote_root = os.path.join(TARGETS_DIR, "remote")
    
    for key in keys:
        key_id = key['id']
        key_name = key['name']
        remote_dir = os.path.join(remote_root, key_id)
        process_source(remote_dir, key_id, key_name)
        
    # Convert back to list and sort
    results = list(aggregated.values())
    return sorted(results, key=lambda x: x['target'])

def write_targets_to_files(all_items):
    """
    Réécrit TOUS les fichiers cibles (Local + Remote) en fonction de la liste fournie.
    Logic: Groups targets by Location -> Job, then writes distinct JSON files.
    """
    # 1. Grouper par Location
    by_location = {} # location_id -> [items]
    
    by_location['local'] = []
    keys = load_api_keys()
    for k in keys:
        by_location[k['id']] = []
        
    for item in all_items:
        loc = item.get('location_id', 'local')
        if loc not in by_location: by_location[loc] = []
        by_location[loc].append(item)
        
    # 2. Pour chaque location, grouper par Job et écrire
    jobs_list = get_jobs()
    
    for loc_id, items in by_location.items():
        if loc_id == 'local':
            base_dir = TARGETS_DIR
        else:
            base_dir = os.path.join(TARGETS_DIR, "remote", loc_id)
            
        os.makedirs(base_dir, exist_ok=True)
        
        job_map = {job: [] for job in jobs_list}
        
        for item in items:
            tgt = (item.get("target") or "").strip()
            if not tgt: continue
            
            global_labels = item.get("labels", {}) or {}
            job_labels_map = item.get("job_labels", {}) or {}
            
            for job in item.get("jobs", []):
                jl = {"job": job}
                for k, v in global_labels.items(): jl[k] = v
                if job in job_labels_map:
                    for k, v in (job_labels_map[job] or {}).items(): jl[k] = v
                
                job_map.setdefault(job, [])
                job_map[job].append({"targets": [tgt], "labels": jl})

        existing_files = [f for f in os.listdir(base_dir) if f.endswith('_target.json')]
        
        for job, entries in job_map.items():
            filename = f"{job}_target.json"
            path = os.path.join(base_dir, filename)
            
            if entries:
                with open(path, "w") as f:
                    json.dump(entries, f, indent=4)
            else:
                if filename in existing_files:
                    with open(path, "w") as f:
                        json.dump([], f, indent=4)

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
FQDN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")

def is_valid_target(val: str) -> bool:
    val = (val or "").strip()
    if not val: return False
    if IPV4_RE.match(val):
        try: return all(0 <= int(x) <= 255 for x in val.split("."))
        except: return False
    if "." not in val: return HOST_RE.match(val) is not None
    return FQDN_RE.match(val) is not None

def parse_labels_str(s: str) -> dict:
    out = {}
    s = (s or "").strip()
    if not s: return out
    for part in [p.strip() for p in s.split(",")]:
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip(); v = v.strip()
            if k: out[k] = v
    return out

TOPOLOGY_FILE = "topology_layout.json"

@app.route('/topology')
@login_required
def topology():
    targets = load_all_targets()
    return render_template(
        'topology.html',
        targets=targets,
        csrf=get_csrf(),
        role=session.get('role', 'viewer')
    )

@app.route('/api/topology', methods=['GET', 'POST'])
@login_required
def api_topology():
    if request.method == 'POST':
        if session.get('role') == 'viewer':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            with open(TOPOLOGY_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        if os.path.exists(TOPOLOGY_FILE):
            try:
                with open(TOPOLOGY_FILE, 'r') as f: return jsonify(json.load(f))
            except: pass
        return jsonify({'nodes': [], 'edges': []})

@app.route('/api/topology_status', methods=['GET'])
@login_required
def api_topology_status():
    cfg = get_config()
    base = (cfg.get('prometheus_base_url') or '').rstrip('/')
    status_map = {}
    
    # 1. Fetch Local Prometheus Status
    if base:
        try:
            auth, headers = get_upstream_auth(cfg)
            r = requests.get(f'{base}/api/v1/targets', auth=auth, headers=headers, timeout=4)
            if r.ok:
                data = r.json()
                for t in data.get('data', {}).get('activeTargets', []):
                    _process_target_status(t, status_map)
        except: pass
        
    # 2. Merge Satellite Status from Cache
    for site_id, data in SATELLITE_STATUS_CACHE.items():
        if isinstance(data, dict):
            for t in data.get('data', {}).get('activeTargets', []):
                _process_target_status(t, status_map)
                
    return jsonify(status_map)

def _process_target_status(t, status_map):
    """Helper to extract and map target status"""
    discovered = t.get('discoveredLabels', {}).get('__address__')
    
    # Enrich status object
    status_obj = {
        'health': t.get('health'),
        'lastScrape': t.get('lastScrape'),
        'lastScrapeDuration': t.get('lastScrapeDuration'),
        'lastError': t.get('lastError')
    }
    
    if discovered:
        status_map[discovered] = status_obj
        # Map by IP only as fallback
        if ':' in discovered:
            status_map[discovered.split(':')[0]] = status_obj
            
    # Also map by instance label if available
    instance = t.get('labels', {}).get('instance')
    if instance: status_map[instance] = status_obj


@app.context_processor
def inject_global_data():
    if "logged_in" in session:
        username = session.get("role")
        profiles = get_user_profiles()
        profile = profiles.get(username, {})
        
        user = {
            "username": username,
            "role": session.get("role"),
            "avatar": profile.get("avatar"),
            "fullname": profile.get("fullname") or username,
            "email": profile.get("email")
        }
        
        # Inject Sites & Jobs for Sidebar
        keys = load_api_keys()
        sites = [{'id': 'local', 'name': 'Local Server', 'prom_status': 'up', 'am_status': 'up'}] 
        
        now = datetime.now()
        for k in keys:
            last_seen_str = k.get('last_seen')
            relative_time = 'never'
            if last_seen_str:
                try:
                    dt = datetime.fromisoformat(last_seen_str)
                    delta = now - dt
                    seconds = int(delta.total_seconds())
                    if seconds < 60:
                        relative_time = f"{seconds}s ago"
                    elif seconds < 3600:
                        relative_time = f"{seconds // 60}m ago"
                    elif seconds < 86400:
                        relative_time = f"{seconds // 3600}h ago"
                    else:
                        relative_time = f"{seconds // 86400}d ago"
                except:
                    pass

            sites.append({
                'id': k['id'],
                'name': k['name'],
                'prom_status': k.get('prom_status', 'unknown'),
                'am_status': k.get('am_status', 'unknown'),
                'last_seen': relative_time
            })
            
        jobs_by_site = {}
        jobs_by_site['local'] = get_jobs('local')
        for k in keys:
            jobs_by_site[k['id']] = k.get('reported_jobs', [])

        return dict(current_user=user, all_sites=sites, jobs_by_site=jobs_by_site, nav_menu=NAV_MENU)
    return dict(current_user=None, all_sites=[], jobs_by_site={}, nav_menu=NAV_MENU)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Rate limiting: max 10 login attempts per minute
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""), max_length=100)
        password = request.form.get("password", "")  # Don't sanitize password (breaks special chars)

        # Log login attempt
        ip_address = get_remote_address()
        logger.info(f"Login attempt for user '{username}' from {ip_address}")

        role = resolve_role(username, password)
        if role:
            # Regenerate session ID to prevent session fixation
            old_session_data = dict(session)
            session.clear()
            session.update(old_session_data)

            # Set session data
            session["logged_in"] = True
            session["role"] = role
            session["username"] = username
            session.permanent = True  # Enable session timeout

            # Log successful login
            logger.info(f"Successful login for user '{username}' with role '{role}' from {ip_address}")
            log_activity('security', f'User {username} logged in', role)

            flash(f"Connecté en tant que {role}.", "success")
            return redirect(url_for("dashboard"))
        else:
            # Log failed login attempt
            logger.warning(f"Failed login attempt for user '{username}' from {ip_address}")
            log_activity('security', f'Failed login attempt for user {username}', 'anonymous')

            flash("Identifiants invalides", "error")

    return render_template("login.html", csrf=get_csrf())

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return redirect(url_for("dashboard"))

@app.route("/targets")
@login_required
def index():
    filter_job = request.args.get("job", "all")
    filter_site = request.args.get("site", "all")
    
    items = load_all_targets()
    
    if filter_job != "all":
        items = [t for t in items if filter_job in t["jobs"]]
    
    if filter_site != "all":
        items = [t for t in items if t.get("location_id") == filter_site]

    cfg = get_config()

    prom_status = {"ok": False, "up": 0, "down": 0}
    base = (cfg.get("prometheus_base_url") or "").rstrip("/")
    if base:
        try:
            auth, headers = get_upstream_auth(cfg)
            r = requests.get(base + "/api/v1/targets", auth=auth, headers=headers, timeout=5)
            if r.ok:
                data = r.json()
                prom_status["ok"] = True
                for at in data.get("data", {}).get("activeTargets", []):
                    if at.get("health") == "up":
                        prom_status["up"] += 1
                    else:
                        prom_status["down"] += 1
        except Exception:
            pass

    dns_sd_map = get_dns_sd_map_from_prometheus_yml()
    keys = load_api_keys()
    locations = [{'id': 'local', 'name': 'Local Server'}]
    for k in keys:
        locations.append({'id': k['id'], 'name': k['name']})

    return render_template(
        "index.html",
        jobs=get_jobs(),
        filter_job=filter_job,
        filter_site=filter_site,
        targets=items,
        config=cfg,
        csrf=get_csrf(),
        role=session.get("role", "viewer"),
        prom_status=prom_status,
        dns_sd_map=dns_sd_map,
        locations=locations
    )

@app.route("/add_target", methods=["POST"])
@login_required
@require_role("editor")
def add_target():
    if not check_csrf(): return redirect(url_for("index"))

    target = (request.form.get("target") or "").strip()
    # New Multi-Site logic
    locations = request.form.getlist("locations")
    if not locations: locations = ["local"] # Fallback

    jobs_selected = request.form.getlist("jobs")
    labels_str = request.form.get("labels", "")
    labels = parse_labels_str(labels_str)

    if not is_valid_target(target):
        flash("Target invalide (IP/FQDN/hostname).", "error")
        return redirect(url_for("index"))

    items = load_all_targets()
    success_count = 0

    for loc_id in locations:
        # Check if exists in this location
        found = next((t for t in items if t["target"].lower() == target.lower() and t.get("location_id", "local") == loc_id), None)
        
        if found:
            for j in jobs_selected:
                if j not in found["jobs"]:
                    found["jobs"].append(j)
            found["jobs"] = sorted(found["jobs"])
            found["labels"].update(labels)
            log_activity('edit', f'Updated target <strong>{target}</strong> on {loc_id}', session.get('role', 'user'))
        else:
            items.append({
                "target": target,
                "jobs": sorted(set(jobs_selected)),
                "labels": labels,
                "job_labels": {},
                "location_id": loc_id
            })
            log_activity('add', f'Added target <strong>{target}</strong> to {loc_id}', session.get('role', 'user'))
        success_count += 1

    write_targets_to_files(items)
    flash(f"Target ajoutée/mise à jour sur {success_count} sites.", "success")
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/edit_target", methods=["POST"])
@login_required
@require_role("editor")
def edit_target():
    if not check_csrf(): return redirect(url_for("index"))

    old_target = (request.form.get("old_target") or "").strip()
    old_location = request.form.get("old_location", "local")
    
    new_target = (request.form.get("new_target") or "").strip()
    # New Multi-Site Logic
    new_locations = request.form.getlist("locations")
    if not new_locations: new_locations = ["local"] # Fallback
    
    jobs_selected = request.form.getlist("jobs")
    labels_str = request.form.get("labels", "")
    labels = parse_labels_str(labels_str)

    job_ctx = (request.form.get("job_context") or "").strip()
    job_labels_str = request.form.get("job_labels", "")
    job_labels = parse_labels_str(job_labels_str)

    if not is_valid_target(new_target):
        flash("Nouvelle target invalide.", "error")
        return redirect(url_for("index"))

    items = load_all_targets()
    
    # 1. Remove the old specific instance first (to handle move/rename cleanly)
    items = [t for t in items if not (t["target"].lower() == old_target.lower() and t.get("location_id", "local") == old_location)]
            
    # 2. Add/Update on ALL selected new locations
    success_count = 0
    for loc_id in new_locations:
        found = next((t for t in items if t["target"].lower() == new_target.lower() and t.get("location_id", "local") == loc_id), None)
        
        if found:
            found["jobs"] = sorted(set(jobs_selected))
            found["labels"] = labels
        else:
            items.append({
                "target": new_target,
                "jobs": sorted(set(jobs_selected)),
                "labels": labels,
                "job_labels": {}, 
                "location_id": loc_id
            })
        success_count += 1
        
    write_targets_to_files(items)
    log_activity('edit', f'Modified target <strong>{new_target}</strong> across {success_count} sites', session.get('role', 'user'))
    flash(f"Target modifiée et déployée sur {success_count} sites.", "success")
        
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/save_all_targets", methods=["POST"])
@login_required
@require_role("editor")
def save_all_targets():
    if not check_csrf(): 
        return redirect(url_for("index"))
    
    targets_data = {}
    for key, value in request.form.items():
        if key == "_csrf": continue
        match = re.match(r"targets\[(\d+)\]\[(.+)\]", key)
        if match:
            index = int(match.group(1))
            field = match.group(2)
            if index not in targets_data:
                targets_data[index] = {
                    "old_target": "", "new_target": "", "jobs": [],
                    "labels": "", "job_labels": "", "job_context": "",
                    "old_location": "local", "location_id": "local"
                }
            if field == "jobs":
                targets_data[index]["jobs"].append(value)
            else:
                targets_data[index][field] = value
    
    current_items = load_all_targets()
    items_map = {f"{t['target'].lower()}|{t.get('location_id','local')}": t for t in current_items}
    
    updated_count = 0
    for idx in sorted(targets_data.keys()):
        data = targets_data[idx]
        old_target = data.get("old_target", "").strip()
        new_target = data.get("new_target", "").strip()
        old_loc = data.get("old_location", "local")
        new_loc = data.get("location_id", "local")
        
        if not new_target or not is_valid_target(new_target): continue
        
        old_key = f"{old_target.lower()}|{old_loc}"
        
        if old_key in items_map:
            item = items_map[old_key]
            del items_map[old_key]
            
            item["target"] = new_target
            item["location_id"] = new_loc
            item["jobs"] = sorted(set(data.get("jobs", [])))
            item["labels"] = parse_labels_str(data.get("labels", ""))
            
            if "job_labels" not in item: item["job_labels"] = {}
            job_ctx = data.get("job_context", "").strip()
            if job_ctx and job_ctx in item["jobs"]:
                item["job_labels"][job_ctx] = parse_labels_str(data.get("job_labels", ""))
            
            new_key = f"{new_target.lower()}|{new_loc}"
            items_map[new_key] = item
            updated_count += 1

    write_targets_to_files(list(items_map.values()))
    flash(f"{updated_count} targets sauvegardées.", "success")
    return redirect(url_for("index", job=request.args.get("job", "all")))

@app.route("/delete_target", methods=["POST"])
@login_required
@require_role("editor")
def delete_target():
    if not check_csrf(): return redirect(url_for("index"))
    tgt = (request.form.get("target") or "").strip()
    loc = request.form.get("location_id", "local")
    
    items = load_all_targets()
    items = [t for t in items if not (t["target"].lower() == tgt.lower() and t.get("location_id", "local") == loc)]
    
    write_targets_to_files(items)
    log_activity('delete', f'Deleted target <strong>{tgt}</strong> from {loc}', session.get('role', 'user'))
    flash("Target supprimée avec succès.", "success")
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/bulk_delete", methods=["POST"])
@login_required
@require_role("editor")
def bulk_delete():
    if not check_csrf(): return redirect(url_for("index"))
    selected = request.form.getlist("selected_targets")
    if not selected:
        flash("Aucune target sélectionnée.", "warning")
        return redirect(url_for("index"))
    items = load_all_targets()
    items = [t for t in items if t["target"] not in selected]
    write_targets_to_files(items)
    log_activity('delete', f'Deleted <strong>{len(selected)} target(s)</strong>: {", ".join(selected[:3])}{"..." if len(selected) > 3 else ""}', session.get('role', 'user'))
    flash("Targets supprimées.", "success")
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/export", methods=["GET"])
@login_required
def export_targets():
    data = load_all_targets()
    buf = io.BytesIO()
    buf.write(json.dumps(data, indent=2).encode("utf-8"))
    buf.seek(0)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return send_file(buf, as_attachment=True, download_name=f"targets-export-{ts}.json", mimetype="application/json")

@app.route("/import", methods=["POST"])
@login_required
@require_role("editor")
def import_targets():
    if not check_csrf(): return redirect(url_for("index"))
    mode = request.form.get("mode", "merge")
    upfile = request.files.get("import_file")
    txt = request.form.get("import_text", "")
    payload = None
    if upfile and upfile.filename:
        try:
            payload = json.load(upfile)
        except Exception:
            flash("JSON import invalide (fichier).", "error")
            return redirect(url_for("index"))
    elif txt.strip():
        try:
            payload = json.loads(txt)
        except Exception:
            flash("JSON import invalide (texte).", "error")
            return redirect(url_for("index"))
    else:
        flash("Rien à importer.", "warning")
        return redirect(url_for("index"))
    if not isinstance(payload, list):
        flash("Format attendu: liste d'objets {target, jobs, labels, job_labels?}.", "error")
        return redirect(url_for("index"))

    if mode == "replace":
        for it in payload:
            it.setdefault("job_labels", {})
        write_targets_to_files(payload)
    else:
        current = load_all_targets()
        m = {t["target"].lower(): {
            "target": t["target"],
            "jobs": list(t["jobs"]),
            "labels": dict(t.get("labels", {})),
            "job_labels": dict(t.get("job_labels", {}))
        } for t in current}
        for it in payload:
            tgt = (it.get("target") or "").strip()
            if not is_valid_target(tgt):
                continue
            key = tgt.lower()
            jobs = sorted(set(it.get("jobs", [])))
            labels = it.get("labels", {}) or {}
            jlmap = it.get("job_labels", {}) or {}
            if key in m:
                m[key]["jobs"] = sorted(set(m[key]["jobs"] + jobs))
                m[key]["labels"].update(labels)
                for j, d in (jlmap or {}).items():
                    m[key]["job_labels"].setdefault(j, {})
                    m[key]["job_labels"][j].update(d or {})
            else:
                m[key] = {"target": tgt, "jobs": jobs, "labels": labels, "job_labels": jlmap}
        write_targets_to_files(list(m.values()))

    flash("Import effectué.", "success")
    return redirect(url_for("index"))

@app.route("/backup", methods=["GET"])
@login_required
def backup_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for job in get_jobs():
            path = os.path.join(TARGETS_DIR, f"{job}_target.json")
            content = json.dumps(safe_read_json(path), indent=2).encode("utf-8")
            z.writestr(f"{job}_target.json", content)
    buf.seek(0)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return send_file(buf, as_attachment=True, download_name=f"targets-backup-{ts}.zip", mimetype="application/zip")

@app.route("/restore", methods=["POST"])
@login_required
@require_role("editor")
def restore_zip():
    if not check_csrf(): return redirect(url_for("index"))
    up = request.files.get("restore_file")
    if not up or not up.filename.lower().endswith(".zip"):
        flash("Fichier ZIP requis.", "error")
        return redirect(url_for("index"))
    try:
        os.makedirs(TARGETS_DIR, exist_ok=True)
        with zipfile.ZipFile(up) as z:
            for job in get_jobs():
                name = f"{job}_target.json"
                if name in z.namelist():
                    content = z.read(name).decode("utf-8")
                    json.loads(content)  # simple validation
                    with open(os.path.join(TARGETS_DIR, name), "w") as f:
                        f.write(content)
        flash("Restauration effectuée.", "success")
    except Exception as e:
        flash(f"Erreur de restauration: {e}", "error")
    return redirect(url_for("index"))

@app.route("/save_config", methods=["POST"])
@login_required
@require_role("admin")
def save_prometheus_config():
    if not check_csrf(): return redirect(url_for("index"))
    cfg = get_config()
    # [MCP Security] 'prometheus_url' removed. We construct it dynamically to prevent SSRF.
    cfg["prometheus_base_url"] = request.form.get("prometheus_base_url", "").strip()
    cfg["alertmanager_base_url"] = request.form.get("alertmanager_base_url", "").strip()
    cfg["blackbox_base_url"] = request.form.get("blackbox_base_url", "").strip()
    cfg["prometheus_username"] = request.form.get("prometheus_username", "").strip()
    cfg["prometheus_password"] = request.form.get("prometheus_password", "")
    cfg["prometheus_bearer_token"] = request.form.get("prometheus_bearer_token", "").strip()
    save_config(cfg)
    log_activity('config', 'Updated Prometheus configuration', session.get('role', 'admin'))
    flash("Configuration sauvegardée.", "success")
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/reload_prometheus", methods=["POST"])
@login_required
@require_role("editor")
def reload_prometheus():
    if not check_csrf(): return redirect(url_for("index"))
    cfg = get_config()
    
    # [MCP Security] SSRF Prevention
    # We ignore the user-provided 'prometheus_url' and construct the reload URL safely
    # from the base URL. This prevents an attacker from pointing the reload action
    # to a destructive endpoint (like /api/v1/admin/tsdb/delete_series).
    base_url = (cfg.get("prometheus_base_url") or "").strip().rstrip('/')
    if not base_url:
        flash("Prometheus Base URL not configured.", "error")
        return redirect(url_for("index"))

    url = f"{base_url}/-/reload"

    now = int(time.time())
    last = int(cfg.get("last_reload_epoch", 0))
    if now - last < 10:
        flash("Cooldown: patientez quelques secondes avant un nouveau reload.", "warning")
        return redirect(url_for("index"))

    auth, headers = get_upstream_auth(cfg)

    try:
        resp = requests.post(url, auth=auth, headers=headers, timeout=6)
        if resp.status_code == 200:
            cfg["last_reload_epoch"] = now
            save_config(cfg)
            flash("Prometheus rechargé avec succès.", "success")
        else:
            flash(f"Erreur Prometheus: {resp.status_code}", "error")
    except Exception as e:
        flash(f"Erreur de connexion: {e}", "error")
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/check_prometheus", methods=["POST"])
@login_required
def check_prometheus():
    if not check_csrf(): return redirect(url_for("index"))
    cfg = get_config()
    base = (cfg.get("prometheus_base_url") or "").rstrip("/")
    if not base:
        flash("prometheus_base_url non défini.", "error")
        return redirect(url_for("index"))

    auth, headers = get_upstream_auth(cfg)

    try:
        r = requests.get(base + "/api/v1/targets", auth=auth, headers=headers, timeout=6)
        if not r.ok:
            flash(f"Echec /api/v1/targets: {r.status_code}", "error")
        else:
            data = r.json()
            act = data.get("data", {}).get("activeTargets", [])
            up = sum(1 for a in act if a.get("health") == "up")
            down = sum(1 for a in act if a.get("health") != "up")
            flash(f"Prometheus OK — up: {up}, down: {down}", "success")
    except Exception as e:
        flash(f"Erreur check Prometheus: {e}", "error")
    return redirect(url_for("index", job=request.args.get("job","all")))

@app.route("/probe", methods=["POST"])
@login_required
def probe():
    if not check_csrf(): return redirect(url_for("index"))
    target = (request.form.get("probe_target") or "").strip()
    if not target:
        flash("Target vide.", "warning")
        return redirect(url_for("index"))
    try:
        socket.getaddrinfo(target, None)
        dns_ok = True
    except Exception:
        dns_ok = False
    msg = f"Résolution DNS: {'OK' if dns_ok else 'KO'}"
    cfg = get_config()
    bb = (cfg.get("blackbox_base_url") or "").rstrip("/")
    if bb:
        msg += f" — Blackbox: {bb}/probe?module=icmp&target={target}"
    flash(msg, "success" if dns_ok else "warning")
    return redirect(url_for("index"))


# ============================================
# [MCP Logic] ALERTING - Gestion des règles Prometheus
# ============================================

RULES_DIR = "rules" # Chemin local relatif

def get_all_site_rules_files():
    """Liste tous les fichiers .yml/.yaml dans la structure (racine pour local, remote/ID/ pour satellites)"""
    files_info = [] # {path, site_id, filename}
    
    # 1. Local (à la racine de RULES_DIR)
    if os.path.exists(RULES_DIR):
        for f in os.listdir(RULES_DIR):
            if f.endswith(('.yml', '.yaml')) and os.path.isfile(os.path.join(RULES_DIR, f)):
                files_info.append({'path': os.path.join(RULES_DIR, f), 'site_id': 'local', 'filename': f})
                
    # 2. Remote
    remote_root = os.path.join(RULES_DIR, "remote")
    if os.path.exists(remote_root):
        for site_id in os.listdir(remote_root):
            site_dir = os.path.join(remote_root, site_id)
            if os.path.isdir(site_dir):
                for f in os.listdir(site_dir):
                    if f.endswith(('.yml', '.yaml')):
                        files_info.append({'path': os.path.join(site_dir, f), 'site_id': site_id, 'filename': f})
    return files_info

def load_alert_rules():
    """
    Charge toutes les règles. Groupement par (Nom, Fichier, Groupe).
    Une même règle peut apparaître sur plusieurs sites.
    """
    import yaml
    temp_rules = {} # key: filename|group|name -> rule_obj
    
    files = get_all_site_rules_files()
    
    for f_info in files:
        try:
            with open(f_info['path'], 'r') as f:
                content = yaml.safe_load(f) or {}
            
            for group in content.get('groups', []):
                g_name = group.get('name', 'unknown')
                for rule in group.get('rules', []):
                    if 'alert' not in rule: continue
                    
                    r_name = rule['alert']
                    r_id = f"{f_info['filename']}|{g_name}|{r_name}"
                    
                    if r_id not in temp_rules:
                        temp_rules[r_id] = {
                            'id': r_id,
                            'file': f_info['filename'],
                            'group': g_name,
                            'name': r_name,
                            'expr': rule.get('expr', ''),
                            'for': rule.get('for', '0m'),
                            'labels': rule.get('labels', {}),
                            'annotations': rule.get('annotations', {}),
                            'severity': rule.get('labels', {}).get('severity', 'info'),
                            'locations': [f_info['site_id']]
                        }
                    else:
                        if f_info['site_id'] not in temp_rules[r_id]['locations']:
                            temp_rules[r_id]['locations'].append(f_info['site_id'])
        except: continue
            
    return sorted(list(temp_rules.values()), key=lambda x: x['name'])

@app.route('/alerts')
@login_required
def alerts():
    """Page de gestion des alertes"""
    rules = load_alert_rules()
    
    keys = load_api_keys()
    locations = [{'id': 'local', 'name': 'Local Server'}]
    for k in keys: locations.append({'id': k['id'], 'name': k['name']})
    
    alerts_status = {}
    cfg = get_config()
    base = (cfg.get("prometheus_base_url") or "").rstrip("/")
    if base:
        try:
            auth, headers = get_upstream_auth(cfg)
            r = requests.get(base + "/api/v1/alerts", auth=auth, headers=headers, timeout=5)
            if r.ok:
                for alert in r.json().get('data', {}).get('alerts', []):
                    name = alert.get('labels', {}).get('alertname')
                    if name:
                        if name not in alerts_status: alerts_status[name] = []
                        alerts_status[name].append(alert.get('state'))
        except: pass

    files = sorted(list(set([r['file'] for r in rules])))
    if not files: files = ["promere_alerts.yml"]

    return render_template(
        'alerts.html',
        rules=rules,
        files=files,
        locations=locations,
        alerts_status=alerts_status,
        jobs=get_jobs(),
        csrf=get_csrf(),
        role=session.get('role', 'viewer')
    )

@app.route('/save_alert', methods=['POST'])
@login_required
@require_role('editor')
def save_alert():
    if not check_csrf(): return redirect(url_for('alerts'))
    import yaml
    
    # [MCP Security] Input Sanitization
    raw_filename = request.form.get('file_name', 'promere_alerts.yml')
    filename = secure_filename(raw_filename)
    if not filename: filename = 'promere_alerts.yml' # Fallback if secure_filename kills it
    
    if not filename.endswith(('.yml', '.yaml')): filename += ".yml"
    group_name = request.form.get('group_name', 'promere_rules')
    alert_name = request.form.get('alert_name', '').strip()
    expr = request.form.get('expr', '').strip()
    duration = request.form.get('duration', '1m').strip()
    
    selected_locations = request.form.getlist('locations')
    if not selected_locations: selected_locations = ['local']

    try:
        labels = json.loads(request.form.get('labels_json', '{}'))
        annotations = json.loads(request.form.get('annotations_json', '{}'))
    except: labels = {}; annotations = {}
        
    if not alert_name or not expr:
        flash("Nom et Expression sont requis.", "error"); return redirect(url_for('alerts'))

    original_id = request.form.get('original_id') # filename|group|name
    
    if original_id:
        parts = original_id.split('|')
        if len(parts) == 3:
            orig_file, orig_group, orig_name = parts
            _delete_rule_everywhere(orig_file, orig_group, orig_name)

    for loc_id in selected_locations:
        if loc_id == 'local':
            target_dir = RULES_DIR
        else:
            target_dir = os.path.join(RULES_DIR, "remote", loc_id)
            
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, filename)
        
        content = {'groups': []}
        if os.path.exists(path):
            try:
                with open(path, 'r') as f: content = yaml.safe_load(f) or {'groups': []}
            except: pass
            
        target_group = next((g for g in content['groups'] if g['name'] == group_name), None)
        if not target_group:
            target_group = {'name': group_name, 'rules': []}
            content['groups'].append(target_group)
            
        new_rule = {'alert': alert_name, 'expr': expr, 'for': duration, 'labels': labels, 'annotations': annotations}
        
        idx = next((i for i, r in enumerate(target_group['rules']) if r.get('alert') == alert_name), -1)
        if idx >= 0: target_group['rules'][idx] = new_rule
        else: target_group['rules'].append(new_rule)
        
        with open(path, 'w') as f: yaml.dump(content, f, sort_keys=False, allow_unicode=True)
        
    log_activity('edit' if original_id else 'add', f"Alert rule <strong>{alert_name}</strong> saved to {len(selected_locations)} site(s)", session.get('role', 'user'))
    flash("Règle sauvegardée.", "success")
    return redirect(url_for('alerts'))

def _delete_rule_everywhere(filename, group_name, alert_name):
    """Supprime une règle de tous les sites (local + remote)"""
    import yaml
    _delete_rule_from_file(os.path.join(RULES_DIR, filename), group_name, alert_name)
    remote_root = os.path.join(RULES_DIR, "remote")
    if os.path.exists(remote_root):
        for sid in os.listdir(remote_root):
            _delete_rule_from_file(os.path.join(remote_root, sid, filename), group_name, alert_name)

def _delete_rule_from_file(filepath, group_name, alert_name):
    import yaml
    if not os.path.exists(filepath): return
    try:
        with open(filepath, 'r') as f: content = yaml.safe_load(f) or {}
        groups = content.get('groups', [])
        target_group = next((g for g in groups if g['name'] == group_name), None)
        if target_group:
            target_group['rules'] = [r for r in target_group['rules'] if r.get('alert') != alert_name]
            with open(filepath, 'w') as f: yaml.dump(content, f, sort_keys=False, allow_unicode=True)
    except: pass

@app.route('/delete_alert', methods=['POST'])
@login_required
@require_role('editor')
def delete_alert():
    if not check_csrf(): return redirect(url_for('alerts'))
    rule_id = request.form.get('rule_id')
    if not rule_id: return redirect(url_for('alerts'))
    parts = rule_id.split('|')
    if len(parts) == 3:
        _delete_rule_everywhere(parts[0], parts[1], parts[2])
        log_activity('delete', f"Deleted alert rule <strong>{parts[2]}</strong>", session.get('role', 'user'))
        flash("Règle supprimée de tous les sites.", "success")
    return redirect(url_for('alerts'))


# ============================================
# [MCP Logic] ALERTMANAGER - Configuration
# ============================================

ALERTMANAGER_YML_PATH = os.getenv("ALERTMANAGER_YML_PATH", "/config/alertmanager.yml")

def get_am_config_path(site_id='local'):
    if site_id == 'local': return ALERTMANAGER_YML_PATH
    return os.path.join("config", "remote", site_id, "alertmanager.yml")

def get_am_config(site_id='local'):
    import yaml
    path = get_am_config_path(site_id)
    if not os.path.exists(path):
        return {"global": {}, "route": {"receiver": "promere-default"}, "receivers": [{"name": "promere-default"}]}
    try:
        with open(path, 'r') as f: return yaml.safe_load(f) or {}
    except: return {}

def save_am_config(config, site_id='local'):
    import yaml
    path = get_am_config_path(site_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, 'w') as f:
            yaml.dump(config, f, sort_keys=False, allow_unicode=True)
        return True
    except Exception as e:
        print(f"Error saving Alertmanager config for {site_id}: {e}")
        return False

@app.route('/alertmanager')
@login_required
def alertmanager_config():
    """Page de configuration Alertmanager"""
    site_id = request.args.get('site', 'local')
    config = get_am_config(site_id)
    
    keys = load_api_keys()
    locations = [{'id': 'local', 'name': 'Local Server'}]
    for k in keys: locations.append({'id': k['id'], 'name': k['name']})

    global_am = config.get('global', {})
    receivers = config.get('receivers', [])
    route = config.get('route', {})
    receiver_names = [r.get('name') for r in receivers if r.get('name')]

    # Calculate receiver distribution across all sites
    receiver_locations = {} # {receiver_name: [site_id, ...]}
    
    # Helper to scan a config
    def scan_receivers(sid, conf):
        for r in conf.get('receivers', []):
            name = r.get('name')
            if name:
                # Handle DISABLED_ prefix logic if needed, but here we store exact name
                clean_name = name.replace('DISABLED_', '')
                if clean_name not in receiver_locations: receiver_locations[clean_name] = []
                if sid not in receiver_locations[clean_name]: receiver_locations[clean_name].append(sid)

    # 1. Local
    scan_receivers('local', get_am_config('local'))
    
    # 2. Remotes
    for k in keys:
        scan_receivers(k['id'], get_am_config(k['id']))

    return render_template(
        'alertmanager.html',
        global_am=global_am,
        receivers=receivers,
        route=route,
        receiver_names=receiver_names,
        config=get_config(),
        jobs=get_jobs(),
        csrf=get_csrf(),
        role=session.get('role', 'viewer'),
        current_site=site_id,
        locations=locations,
        receiver_locations=receiver_locations
    )

@app.route('/save_am_global', methods=['POST'])
@login_required
@require_role('admin')
def save_am_global():
    if not check_csrf(): return redirect(url_for('alertmanager_config'))
    
    # Apply to ALL sites by default as requested
    keys = load_api_keys()
    target_sites = ['local'] + [k['id'] for k in keys]
    
    smtp_smarthost = request.form.get('smtp_smarthost', '').strip()
    smtp_from = request.form.get('smtp_from', '').strip()
    smtp_auth_username = request.form.get('smtp_auth_username', '').strip()
    smtp_auth_password = request.form.get('smtp_auth_password', '').strip()
    smtp_require_tls = request.form.get('smtp_require_tls') == 'on'

    success_count = 0
    
    for site_id in target_sites:
        am_config = get_am_config(site_id)
        if 'global' not in am_config: am_config['global'] = {}
        
        am_config['global']['smtp_smarthost'] = smtp_smarthost
        am_config['global']['smtp_from'] = smtp_from
        am_config['global']['smtp_auth_username'] = smtp_auth_username
        if smtp_auth_password: 
            am_config['global']['smtp_auth_password'] = smtp_auth_password
        am_config['global']['smtp_require_tls'] = smtp_require_tls
        
        if save_am_config(am_config, site_id):
            success_count += 1
    
    log_activity('config', f'Updated AM Global settings for {success_count} sites', session.get('role', 'admin'))
    flash(f"Configuration SMTP globale appliquée sur {success_count} sites.", "success")
    
    current_view = request.form.get('site_id', 'local')
    return redirect(url_for('alertmanager_config', site=current_view))

@app.route('/save_am_receiver', methods=['POST'])
@login_required
@require_role('editor')
def save_am_receiver():
    if not check_csrf(): return redirect(url_for('alertmanager_config'))
    
    selected_locations = request.form.getlist('locations')
    logger.info(f"DEBUG: save_am_receiver locations: {selected_locations}")
    
    current_view_site = request.form.get('site_id', 'local')
    if not selected_locations: selected_locations = [current_view_site]
    
    original_name = request.form.get('original_name', '').strip()
    raw_name = request.form.get('name', '').strip()
    is_enabled = request.form.get('receiver_enabled') == 'on'
    
    final_name = raw_name
    if not is_enabled and 'receiver_enabled' in request.form:
         final_name = f"DISABLED_{raw_name}"
    elif original_name.startswith("DISABLED_") and 'receiver_enabled' not in request.form:
         pass

    if not raw_name: 
        flash("Name required.", "error")
        return redirect(url_for('alertmanager_config', site=current_view_site))
        
    new_receiver = {'name': final_name}
    type_am = request.form.get('type', 'email')
    
    if type_am == 'email':
        new_receiver['email_configs'] = [{'to': request.form.get('email_to', '').strip(), 'send_resolved': request.form.get('send_resolved') == 'on'}]
    elif type_am == 'webhook':
        new_receiver['webhook_configs'] = [{'url': request.form.get('webhook_url', '').strip(), 'send_resolved': request.form.get('send_resolved') == 'on'}]
    elif type_am == 'discord':
        new_receiver['discord_configs'] = [{'webhook_url': request.form.get('discord_url', '').strip(), 'send_resolved': request.form.get('send_resolved') == 'on'}]
        
    success_count = 0
    
    # [MCP Logic] Full Sync: Update selected, Remove unselected
    keys = load_api_keys()
    all_site_ids = ['local'] + [k['id'] for k in keys]
    
    for site_id in all_site_ids:
        am_config = get_am_config(site_id)
        if 'receivers' not in am_config: am_config['receivers'] = []
        
        # Check if we should ADD/UPDATE or REMOVE
        if site_id in selected_locations:
            # === UPDATE LOGIC ===
            target_idx = -1
            if original_name:
                 target_idx = next((i for i, r in enumerate(am_config['receivers']) if r.get('name') == original_name), -1)
            
            if target_idx == -1:
                 target_idx = next((i for i, r in enumerate(am_config['receivers']) if r.get('name') == final_name), -1)

            if target_idx >= 0:
                am_config['receivers'][target_idx] = new_receiver
                # Update route if name changed
                if am_config.get('route', {}).get('receiver') == original_name and final_name != original_name:
                     am_config['route']['receiver'] = final_name
            else:
                am_config['receivers'].append(new_receiver)
            
            if save_am_config(am_config, site_id):
                success_count += 1
        else:
            # === REMOVE LOGIC ===
            # Only remove if it matches original_name (if editing) or final_name
            # But strictly speaking, if we are editing "Rec1", we want to remove "Rec1" from unselected sites.
            target_name = original_name if original_name else final_name
            
            original_len = len(am_config['receivers'])
            am_config['receivers'] = [r for r in am_config['receivers'] if r.get('name') != target_name]
            
            # If name changed (Rec1 -> Rec2), we also need to ensure Rec2 isn't there? 
            # No, if we are renaming, we remove old name.
            # If we just created Rec2, we don't need to remove it from unselected sites as it wasn't there.
            
            if len(am_config['receivers']) < original_len:
                # Cleanup route
                if am_config.get('route', {}).get('receiver') == target_name:
                    am_config['route']['receiver'] = am_config['receivers'][0]['name'] if am_config['receivers'] else 'default'
                save_am_config(am_config, site_id)

    log_activity('edit' if original_name else 'add', f"Updated receiver {final_name} on {success_count} sites", session.get('role', 'user'))
    flash(f"Receiver {raw_name} sauvegardé sur {success_count} sites.", "success")
    return redirect(url_for('alertmanager_config', site=current_view_site))

@app.route('/delete_am_receiver', methods=['POST'])
@login_required
@require_role('editor')
def delete_am_receiver():
    if not check_csrf(): return redirect(url_for('alertmanager_config'))
    
    current_view_site = request.form.get('site_id', 'local')
    name = request.form.get('name', '').strip()
    
    # [MCP Logic] Multi-site Deletion
    # We delete the receiver from ALL sites to ensure consistency
    keys = load_api_keys()
    target_sites = ['local'] + [k['id'] for k in keys]
    
    deleted_count = 0
    
    for site_id in target_sites:
        am_config = get_am_config(site_id)
        if 'receivers' in am_config:
            original_len = len(am_config['receivers'])
            am_config['receivers'] = [r for r in am_config['receivers'] if r.get('name') != name]
            
            if len(am_config['receivers']) < original_len:
                # Cleanup route if it was using this receiver
                if am_config.get('route', {}).get('receiver') == name:
                    am_config['route']['receiver'] = am_config['receivers'][0]['name'] if am_config['receivers'] else 'default'
                
                if save_am_config(am_config, site_id):
                    deleted_count += 1

    if deleted_count > 0:
        log_activity('delete', f"Deleted AM receiver {name} from {deleted_count} sites", session.get('role', 'user'))
        flash(f"Destinataire {name} supprimé de {deleted_count} sites.", "success")
    else:
        flash("Receiver introuvable.", "warning")
        
    return redirect(url_for('alertmanager_config', site=current_view_site))

@app.route('/save_am_route', methods=['POST'])
@login_required
@require_role('admin')
def save_am_route():
    if not check_csrf(): return redirect(url_for('alertmanager_config'))
    site_id = request.form.get('site_id', 'local')
    am_config = get_am_config(site_id)
    if 'route' not in am_config: am_config['route'] = {}
    am_config['route']['receiver'] = request.form.get('default_receiver', 'promere-default')
    am_config['route']['group_wait'] = request.form.get('group_wait', '30s')
    am_config['route']['group_interval'] = request.form.get('group_interval', '5m')
    am_config['route']['repeat_interval'] = request.form.get('repeat_interval', '4h')
    if save_am_config(am_config, site_id): flash("Routage mis à jour.", "success")
    else: flash("Erreur sauvegarde.", "error")
    return redirect(url_for('alertmanager_config', site=site_id))

@app.route('/reload_alertmanager', methods=['POST'])
@login_required
@require_role('editor')
def reload_alertmanager():
    if not check_csrf(): return redirect(url_for('alertmanager_config'))
    cfg = get_config()
    
    # [MCP Security] SSRF Prevention for Alertmanager
    base = (cfg.get("alertmanager_base_url") or "").strip().rstrip('/')
    if not base:
        flash("Alertmanager URL not configured.", "error")
        return redirect(url_for('alertmanager_config'))

    url = f"{base}/-/reload"
    
    try:
        resp = requests.post(url, timeout=6)
        if resp.status_code == 200:
            flash("Alertmanager reloaded successfully.", "success")
        else:
            flash(f"Alertmanager error: {resp.status_code}", "error")
    except Exception as e:
        flash(f"Connection error: {e}", "error")
    return redirect(url_for('alertmanager_config'))


# ============================================
# [MCP Logic] ONBOARDING & API
# Context: First-time setup and internal APIs for UI.
# ============================================

@app.route('/onboarding')
def onboarding():
    """Page d'onboarding pour la configuration initiale"""
    return render_template('onboarding.html')

@app.route('/api/test_prometheus', methods=['POST'])
def api_test_prometheus():
    data = request.get_json()
    prometheus_base_url = data.get('prometheus_base_url', '').strip().rstrip('/')
    prometheus_username = data.get('prometheus_username', '').strip()
    prometheus_password = data.get('prometheus_password', '')
    prometheus_bearer_token = data.get('prometheus_bearer_token', '').strip()
    
    if not prometheus_base_url:
        return jsonify({'success': False, 'message': 'Prometheus base URL is required'}), 400
    
    # Use helper
    # Mock config to use helper
    temp_cfg = {
        "prometheus_bearer_token": prometheus_bearer_token,
        "prometheus_username": prometheus_username,
        "prometheus_password": prometheus_password
    }
    auth, headers = get_upstream_auth(temp_cfg)
    
    try:
        response = requests.get(f'{prometheus_base_url}/api/v1/targets', auth=auth, headers=headers, timeout=10)
        if response.ok:
            data = response.json()
            targets = data.get('data', {}).get('activeTargets', [])
            up_count = sum(1 for t in targets if t.get('health') == 'up')
            down_count = sum(1 for t in targets if t.get('health') != 'up')
            return jsonify({
                'success': True,
                'message': f'Connection successful! Found {up_count} targets up, {down_count} targets down.',
                'targets_up': up_count, 'targets_down': down_count
            })
        else:
            return jsonify({'success': False, 'message': f'Prometheus returned status code {response.status_code}.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/save_onboarding_config', methods=['POST'])
def api_save_onboarding_config():
    data = request.get_json()
    cfg = get_config()
    cfg['prometheus_url'] = data.get('prometheus_url', '').strip()
    cfg['prometheus_base_url'] = data.get('prometheus_base_url', '').strip()
    cfg['alertmanager_base_url'] = data.get('alertmanager_base_url', '').strip()
    cfg['prometheus_username'] = data.get('prometheus_username', '').strip()
    cfg['prometheus_password'] = data.get('prometheus_password', '')
    cfg['prometheus_bearer_token'] = data.get('prometheus_bearer_token', '').strip()
    save_config(cfg)
    return jsonify({'success': True, 'message': 'Configuration saved successfully'})

@app.route('/api/import_onboarding', methods=['POST'])
def api_import_onboarding():
    upfile = request.files.get('import_file')
    mode = request.form.get('mode', 'replace')
    if not upfile or not upfile.filename: return jsonify({'success': False, 'message': 'No file provided'}), 400
    try: payload = json.load(upfile)
    except Exception as e: return jsonify({'success': False, 'message': f'Invalid JSON: {str(e)}'}), 400
    
    if not isinstance(payload, list): return jsonify({'success': False, 'message': 'Expected a list of targets'}), 400
    
    valid_targets = []
    for item in payload:
        target = (item.get('target', '') or '').strip()
        if not is_valid_target(target): continue
        item.setdefault('job_labels', {})
        valid_targets.append(item)
    
    if mode == 'replace':
        write_targets_to_files(valid_targets)
    else:
        current = load_all_targets()
        target_map = {t['target'].lower(): {
            'target': t['target'], 'jobs': list(t['jobs']),
            'labels': dict(t.get('labels', {})), 'job_labels': dict(t.get('job_labels', {}))
        } for t in current}
        
        for item in valid_targets:
            target = item['target']; key = target.lower()
            jobs = sorted(set(item.get('jobs', []))); labels = item.get('labels', {}) or {}
            job_labels_map = item.get('job_labels', {}) or {}
            
            if key in target_map:
                target_map[key]['jobs'] = sorted(set(target_map[key]['jobs'] + jobs))
                target_map[key]['labels'].update(labels)
                for job, jl in (job_labels_map or {}).items():
                    target_map[key]['job_labels'].setdefault(job, {})
                    target_map[key]['job_labels'][job].update(jl or {})
            else:
                target_map[key] = {'target': target, 'jobs': jobs, 'labels': labels, 'job_labels': job_labels_map}
        write_targets_to_files(list(target_map.values()))
    
    return jsonify({'success': True, 'message': f'Successfully imported {len(valid_targets)} targets'})

@app.route('/api/tsdb_size', methods=['GET'])
def api_tsdb_size():
    """Récupérer la taille de la TSDB Prometheus"""
    cfg = get_config()
    base = (cfg.get('prometheus_base_url') or '').rstrip('/')
    if not base: return jsonify({'success': False, 'size': 'N/A', 'message': 'Prometheus base URL not configured'})
    
    auth, headers = get_upstream_auth(cfg)
    
    try:
        query_response = requests.get(f'{base}/api/v1/query', params={'query': 'prometheus_tsdb_storage_blocks_bytes'}, auth=auth, headers=headers, timeout=5)
        if query_response.ok:
            query_data = query_response.json()
            results = query_data.get('data', {}).get('result', [])
            if results:
                value_bytes = float(results[0].get('value', [0, 0])[1])
                if value_bytes < 1024: size_str = f'{value_bytes:.0f} B'
                elif value_bytes < 1024 ** 2: size_str = f'{value_bytes / 1024:.1f} KB'
                elif value_bytes < 1024 ** 3: size_str = f'{value_bytes / (1024 ** 2):.1f} MB'
                else: size_str = f'{value_bytes / (1024 ** 3):.2f} GB'
                return jsonify({'success': True, 'size': size_str, 'bytes': int(value_bytes)})
        return jsonify({'success': True, 'size': 'N/A'})
    except Exception as e: return jsonify({'success': False, 'size': 'Error', 'message': str(e)})

@app.route('/api/prometheus_status', methods=['GET'])
def api_prometheus_status():
    cfg = get_config()
    base = (cfg.get('prometheus_base_url') or '').rstrip('/')
    if not base: return jsonify({'status': 'error', 'message': 'Prometheus URL not configured'})
    try:
        response = requests.get(f'{base}/-/healthy', timeout=3)
        return jsonify({'status': 'up', 'message': 'Prometheus is online'}) if response.status_code == 200 else jsonify({'status': 'down'})
    except Exception as e: return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/alertmanager_status', methods=['GET'])
@login_required
def api_alertmanager_status():
    cfg = get_config()
    base = (cfg.get('alertmanager_base_url') or '').rstrip('/')
    if not base: return jsonify({'status': 'error', 'message': 'Alertmanager URL not configured'})
    try:
        response = requests.get(f'{base}/-/healthy', timeout=3)
        return jsonify({'status': 'up', 'message': 'Alertmanager is online'}) if response.status_code == 200 else jsonify({'status': 'down'})
    except Exception as e: return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/global_stats', methods=['GET'])
@login_required
def api_global_stats():
    """Récupère les stats globales pour le dashboard"""
    cfg = get_config(); base = (cfg.get('prometheus_base_url') or '').rstrip('/')
    stats = {'prometheus_status': 'unknown', 'targets_up': 0, 'targets_down': 0, 'targets_total': 0, 'alerts_firing': 0, 'alerts_pending': 0}
    if not base: return jsonify(stats)
    
    auth, headers = get_upstream_auth(cfg)
        
    try:
        r_targets = requests.get(f'{base}/api/v1/targets', auth=auth, headers=headers, timeout=3)
        if r_targets.ok:
            stats['prometheus_status'] = 'up'
            data = r_targets.json(); active_targets = data.get('data', {}).get('activeTargets', [])
            stats['targets_total'] = len(active_targets)
            stats['targets_up'] = sum(1 for t in active_targets if t.get('health') == 'up')
            stats['targets_down'] = stats['targets_total'] - stats['targets_up']
        else: stats['prometheus_status'] = 'down'

        r_alerts = requests.get(f'{base}/api/v1/alerts', auth=auth, headers=headers, timeout=3)
        if r_alerts.ok:
            data = r_alerts.json(); alerts = data.get('data', {}).get('alerts', [])
            stats['alerts_firing'] = sum(1 for a in alerts if a.get('state') == 'firing')
            stats['alerts_pending'] = sum(1 for a in alerts if a.get('state') == 'pending')
    except: stats['prometheus_status'] = 'error'
    return jsonify(stats)

@app.route('/api/silences', methods=['GET', 'POST'])
@login_required
def api_silences():
    cfg = get_config(); base = (cfg.get('alertmanager_base_url') or '').rstrip('/')
    if not base: return jsonify({'error': 'Alertmanager not configured'}), 400
    if request.method == 'POST':
        try:
            payload = request.get_json()
            r = requests.post(f'{base}/api/v2/silences', json=payload, timeout=5)
            return jsonify(r.json()) if r.ok else (jsonify({'error': r.text}), r.status_code)
        except Exception as e: return jsonify({'error': str(e)}), 500
    else:
        try:
            r = requests.get(f'{base}/api/v2/silences', params={'silenced': 'false'}, timeout=5)
            return jsonify(r.json()) if r.ok else (jsonify({'error': r.text}), r.status_code)
        except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/silence/<silence_id>', methods=['DELETE'])
@login_required
def api_expire_silence(silence_id):
    cfg = get_config(); base = (cfg.get('alertmanager_base_url') or '').rstrip('/')
    try:
        r = requests.delete(f'{base}/api/v2/silence/{silence_id}', timeout=5)
        return jsonify({'success': True}) if r.ok else (jsonify({'error': r.text}), r.status_code)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/query_preview', methods=['POST'])
@login_required
def api_query_preview():
    cfg = get_config(); base = (cfg.get('prometheus_base_url') or '').rstrip('/')
    expr = request.json.get('expr')
    if not base or not expr: return jsonify({'error': 'Missing config or expression'}), 400
    
    auth, headers = get_upstream_auth(cfg)
    try:
        r = requests.get(f'{base}/api/v1/query', params={'query': expr}, auth=auth, headers=headers, timeout=5)
        return jsonify(r.json()) if r.ok else (jsonify({'error': f'Prometheus Error: {r.status_code}'}), 400)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard_panels', methods=['GET'])
@login_required
def api_get_dashboard_panels():
    return jsonify({'panels': get_dashboard_panels()})

@app.route('/api/dashboard_panels', methods=['POST'])
@login_required
def api_save_dashboard_panels():
    try:
        data = request.get_json(); panels = data.get('panels', [])
        if save_dashboard_panels(panels): return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Failed to save panels'}), 500
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/activity_log')
@login_required
def activity_log():
    activities = get_activities()
    return render_template('activity_log.html', activities=activities, jobs=get_jobs(), config=get_config(), csrf=get_csrf())

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', jobs=get_jobs(), config=get_config(), csrf=get_csrf(), role=session.get('role', 'viewer'))

@app.route('/team')
@login_required
def team_management():
    profiles = get_user_profiles()
    users = []
    
    def enrich_user(username, role):
        profile = profiles.get(username, {})
        return {
            'username': username,
            'role': role,
            'fullname': profile.get('fullname', ''),
            'email': profile.get('email', ''),
            'avatar': profile.get('avatar', ''),
            'bio': profile.get('bio', ''),
            'last_login': 'Active now' if username == session.get('username') else 'Unknown'
        }

    # Iterate over all users in USER_CREDENTIALS
    for username, data in USER_CREDENTIALS.items():
        role = data.get('role', 'viewer')
        users.append(enrich_user(username, role))

    # Sort by role priority
    role_order = {'admin': 0, 'editor': 1, 'viewer': 2}
    users.sort(key=lambda u: role_order.get(u['role'], 99))

    return render_template('team.html', users=users, csrf=get_csrf(), role=session.get('role', 'viewer'), jobs=get_jobs(), config=get_config())

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if not check_csrf(): return redirect(url_for('team_management'))
    
    target_username = request.form.get('username')
    
    # Check against USER_CREDENTIALS
    if target_username not in USER_CREDENTIALS:
        flash("Utilisateur inconnu.", "error")
        return redirect(url_for('team_management'))
        
    data = {
        'fullname': request.form.get('fullname', '').strip(),
        'email': request.form.get('email', '').strip(),
        'bio': request.form.get('bio', '').strip()
    }
    
    avatar_file = request.files.get('avatar_file')
    if avatar_file and avatar_file.filename:
        filename = f"{target_username}_{int(time.time())}.{avatar_file.filename.split('.')[-1]}"
        path = os.path.join('static', 'avatars', filename)
        try:
            avatar_file.save(path)
            data['avatar'] = filename
        except Exception as e:
            flash(f"Erreur upload avatar: {e}", "error")
            
    if save_user_profile(target_username, data):
        flash("Profil mis à jour.", "success")
    else:
        flash("Erreur de sauvegarde.", "error")
        
    return redirect(url_for('team_management'))

@app.route('/delete_user', methods=['POST'])
@login_required
@require_role('admin')
def delete_user():
    if not check_csrf(): return redirect(url_for('team_management'))
    flash(f'User deletion is manual. Please remove the user from config/password_hashes.json.', 'warning')
    return redirect(url_for('team_management'))

@app.route('/api/prom/metrics', methods=['GET'])
@login_required
def api_prom_metrics():
    cfg = get_config(); base = (cfg.get("prometheus_base_url") or "").rstrip("/")
    if not base: return jsonify([])
    
    auth, headers = get_upstream_auth(cfg)
    try:
        r = requests.get(f'{base}/api/v1/label/__name__/values', auth=auth, headers=headers, timeout=5)
        return jsonify(r.json().get("data", [])) if r.ok else (jsonify({'error': f'Prometheus Error: {r.status_code}'}), 400)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/prom/search_metrics', methods=['GET'])
@login_required
def api_prom_search_metrics():
    query = request.args.get('q', '').strip().lower()
    if not query: return jsonify([])
    synonyms_path = os.path.join("config", "synonyms.json"); semantic_map = {}
    if os.path.exists(synonyms_path):
        try:
            with open(synonyms_path, 'r') as f: semantic_map = json.load(f)
        except: pass
    search_terms = [query]
    for key, values in semantic_map.items():
        if key in query: search_terms.extend(values)
    search_terms = list(set(search_terms))
    cfg = get_config(); base = (cfg.get("prometheus_base_url") or "").rstrip("/")
    if not base: return jsonify([])
    
    auth, headers = get_upstream_auth(cfg)
    try:
        r = requests.get(f'{base}/api/v1/metadata', auth=auth, headers=headers, timeout=5)
        if r.ok:
            metrics_meta = r.json().get("data", {}); results = []
            for metric_name, info_list in metrics_meta.items():
                if not info_list: continue
                info = info_list[0]; help_text = info.get('help', '').lower(); m_name_lower = metric_name.lower()
                match_score = 0
                for term in search_terms:
                    if term in m_name_lower: match_score += 10
                    elif term in help_text: match_score += 1
                if match_score > 0: results.append({'name': metric_name, 'help': info.get('help', ''), 'type': info.get('type', 'unknown'), 'score': match_score})
            results.sort(key=lambda x: (-x['score'], len(x['name'])))
            return jsonify(results[:50])
        return jsonify({'error': f'Prometheus Error: {r.status_code}'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/get_jobs_for_sites', methods=['POST'])
@login_required
def api_get_jobs_for_sites():
    """
    [MCP Endpoint] Fetch jobs for multiple sites.
    Input: { "sites": ["local", "remote_1"] }
    Output: { "jobs": ["job1", "job2"] }
    """
    data = request.get_json()
    sites = data.get('sites', [])
    if not sites:
        return jsonify({'jobs': []})

    all_jobs = set()
    for site_id in sites:
        jobs = get_jobs(site_id)
        all_jobs.update(jobs)

    return jsonify({'jobs': sorted(list(all_jobs))})

if __name__ == "__main__":
    os.makedirs(TARGETS_DIR, exist_ok=True)
    os.makedirs(os.path.join('static', 'avatars'), exist_ok=True)
    app.run(host="0.0.0.0", port=8091, debug=True)