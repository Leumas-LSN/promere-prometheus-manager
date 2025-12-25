"""
[MCP Context] Promere Satellite Agent
======================================
Role: Bridge between Promere Central and Local Infrastructure.
Architecture: Pull-Model. This agent runs inside the remote infrastructure (behind NAT/Firewall) 
and polls the Central API for configuration updates. It then writes these configurations 
to local files (targets, rules, main configs) and reloads local services.

Core Responsibilities:
1. Health Reporting: Checks local Prometheus/Alertmanager health and reports to Central.
2. Configuration Sync: Downloads Targets JSON and Rules YAML from Central.
3. Service Management: Reloads local services (/-/reload) upon config changes.
4. Discovery: Parses local prometheus.yml to report available jobs to Central.

Dependencies: 
- Local Prometheus & Alertmanager instances reachable via HTTP.
- Write access to /etc/prometheus/ and /etc/alertmanager/.
"""

import os
import time
import json
import hashlib
import requests
import sys
import logging

# ==========================================
# [MCP] Configuration & Environment
# Context: Loaded at startup. Critical for connectivity.
# ==========================================
CENTRAL_URL = os.getenv("CENTRAL_URL", "http://localhost:8091")
API_KEY = os.getenv("API_KEY", "") # Authentication with Central
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "60"))
SYNC_BASE_CONFIGS = os.getenv("SYNC_BASE_CONFIGS", "true").lower() == "true" # Whether to sync main .yml files
SYNC_PROM_CONFIG = os.getenv("SYNC_PROM_CONFIG", str(SYNC_BASE_CONFIGS)).lower() == "true"
SYNC_AM_CONFIG = os.getenv("SYNC_AM_CONFIG", str(SYNC_BASE_CONFIGS)).lower() == "true"
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true" # [MCP Security] Toggle SSL verification

PROMETHEUS_BASE_URL = os.getenv("PROMETHEUS_BASE_URL", "http://prometheus:9090")
ALERTMANAGER_BASE_URL = os.getenv("ALERTMANAGER_BASE_URL", "http://alertmanager:9093")

# [MCP] Security: Basic Auth for Local Services
# Used when reloading services or checking health.
PROM_USER = os.getenv("PROMETHEUS_USER", "")
PROM_PASS = os.getenv("PROMETHEUS_PASS", "")
AM_USER = os.getenv("ALERTMANAGER_USER", "")
AM_PASS = os.getenv("ALERTMANAGER_PASS", "")

# [MCP] File System Paths
# These paths must be shared volumes with the actual Prometheus/Alertmanager containers.
TARGETS_DIR = os.getenv("TARGETS_DIR", "/etc/prometheus/targets")
RULES_DIR = os.getenv("RULES_DIR", "/etc/prometheus/rules")
PROM_CONFIG_FILE = os.getenv("PROM_CONFIG_FILE", "/etc/prometheus/prometheus.yml")
AM_CONFIG_FILE = os.getenv("AM_CONFIG_FILE", "/etc/alertmanager/alertmanager.yml")

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("satellite-agent")

def calculate_checksum(data):
    """
    [MCP Utility] Checksum Calculator
    Purpose: Detect changes in configuration content to avoid unnecessary disk writes and service reloads.
    Input: Dict, List or String (Configuration content)
    Output: SHA256 Hash string (secure alternative to MD5)
    """
    if isinstance(data, (dict, list)):
        encoded = json.dumps(data, sort_keys=True).encode('utf-8')
    else:
        encoded = str(data).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()

def check_service_health(base_url, user="", password=""):
    """
    [MCP Logic] Service Health Check
    Purpose: Verify if a local service (Prometheus/Alertmanager) is responsive.
    Mechanism: HTTP GET to /-/healthy endpoint.
    Returns: 'up' or 'down' string.
    """
    try:
        auth = (user, password) if user or password else None
        r = requests.get(f"{base_url.rstrip('/')}/-/healthy", auth=auth, timeout=2)
        return "up" if r.status_code == 200 else "down"
    except Exception as e:
        logger.debug(f"Health check failed for {base_url}: {e}")
        return "down"

def get_local_jobs():
    """
    [MCP Discovery] Job Extraction
    Purpose: Parse the local prometheus.yml to understand what scrapers are configured.
    Context: Sent to Central so the UI knows which jobs are available for this specific satellite.
    Dependency: PyYAML (must be installed in container).
    Returns: List of job names (strings).
    """
    if not os.path.exists(PROM_CONFIG_FILE):
        logger.warning(f"Config file not found: {PROM_CONFIG_FILE}")
        return []
    try:
        import yaml
        with open(PROM_CONFIG_FILE, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        jobs = [j.get('job_name') for j in cfg.get('scrape_configs', []) if j.get('job_name')]
        logger.info(f"Found {len(jobs)} jobs in local config.")
        return sorted(list(set(jobs)))
    except Exception as e:
        logger.error(f"Failed to parse prometheus.yml: {e}")
        return []

def get_local_targets_status(base_url, user="", password=""):
    """
    [MCP Discovery] Targets Status Extraction
    Purpose: Query local Prometheus API to get the health status of all scrape targets.
    Context: Sent to Central so the UI can display UP/DOWN status for remote targets.
    """
    try:
        auth = (user, password) if user or password else None
        r = requests.get(f"{base_url.rstrip('/')}/api/v1/targets", auth=auth, timeout=5)
        if r.status_code == 200:
            return r.json() # Return the full JSON response from Prometheus
    except Exception as e:
        logger.error(f"Failed to fetch local targets status: {e}")
    return {}

def sync_and_report_health():
    """
    [MCP Logic] Main Sync Cycle
    Purpose: Two-way sync with Central.
    1. OUTBOUND: Report local health status, available jobs AND targets status.
    2. INBOUND: Receive latest configuration targets and rules.
    
    Security: Uses Bearer Token (API_KEY) for authentication.
    Returns: Tuple (Success: bool, ConfigPayload: dict)
    """
    if not API_KEY: return False, None
    
    headers = {"Authorization": f"Bearer {API_KEY}", "User-Agent": "Promere-Satellite/1.0"}
    
    # 1. Check health and extract jobs
    prom_status = check_service_health(PROMETHEUS_BASE_URL, PROM_USER, PROM_PASS)
    am_status = check_service_health(ALERTMANAGER_BASE_URL, AM_USER, AM_PASS)
    local_jobs = get_local_jobs()
    targets_status = get_local_targets_status(PROMETHEUS_BASE_URL, PROM_USER, PROM_PASS)
    
    # 2. Report health + jobs + targets (POST)
    url = f"{CENTRAL_URL.rstrip('/')}/api/sync/config"
    try:
        payload = {
            "prom_status": prom_status, 
            "am_status": am_status,
            "jobs": local_jobs,
            "targets_status": targets_status
        }
        # Fire and forget health report to not block config fetch if something is weird
        requests.post(url, headers=headers, json=payload, timeout=5, verify=VERIFY_SSL)
    except Exception as e:
        logger.debug(f"Failed to report health status: {e}")
    
    # 3. Get Config (GET)
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=VERIFY_SSL)
        if r.status_code == 200: return True, r.json()
    except Exception as e: logger.error(f"Sync failed: {e}")
    return False, None

def sync_directory(directory, items, is_json=True):
    """
    [MCP IO] Directory Synchronization
    Purpose: Mirror a set of files from Central to a local directory.
    Logic:
    - Writes new/modified files.
    - DELETES files that are no longer in the payload (Clean sync).
    - Checks content hash before writing to minimize IO.
    
    Input: 
    - directory: Path to sync (e.g. /etc/prometheus/targets)
    - items: Dict {filename: content}
    - is_json: Bool (formatting preference)
    
    Returns: True if any change occurred (triggering a reload).
    """
    changes = False
    os.makedirs(directory, exist_ok=True)
    ext = '.json' if is_json else ('.yml', '.yaml')
    existing_files = set(f for f in os.listdir(directory) if f.endswith(ext))
    new_files = set(items.keys())
    
    # Clean up orphaned files
    for filename in existing_files - new_files:
        try:
            os.remove(os.path.join(directory, filename))
            changes = True
            logger.info(f"Removed orphaned file: {filename}")
        except Exception as e:
            logger.error(f"Failed to remove file {filename}: {e}")

    # Write new/updated files
    for filename, content in items.items():
        path = os.path.join(directory, filename)
        current_sum = ""
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    current_sum = calculate_checksum(json.load(f) if is_json else f.read())
            except Exception as e:
                logger.warning(f"Failed to read existing file {path}: {e}")
        if current_sum != calculate_checksum(content):
            try:
                with open(path, 'w') as f:
                    if is_json:
                        json.dump(content, f, indent=2)
                    else:
                        f.write(str(content))
                changes = True
                logger.info(f"Updated file: {filename}")
            except Exception as e:
                logger.error(f"Failed to write file {filename}: {e}")
    return changes

def sync_single_file(filepath, content):
    """
    [MCP IO] Single File Synchronization
    Purpose: Sync global configuration files (prometheus.yml, alertmanager.yml).
    Returns: True if file changed.
    """
    if not content: return False
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    current_sum = ""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                current_sum = calculate_checksum(f.read())
        except Exception as e:
            logger.warning(f"Failed to read existing file {filepath}: {e}")
    if current_sum != calculate_checksum(content):
        try:
            with open(filepath, 'w') as f:
                f.write(content)
            logger.info(f"Updated config file: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to write file {filepath}: {e}")
    return False

def reload_service(base_url, name, user="", password=""):
    """
    [MCP Logic] Service Reload
    Purpose: Trigger a configuration reload (SIGHUP equivalent via HTTP).
    Target: /-/reload endpoint.
    """
    try:
        auth = (user, password) if user or password else None
        url = f"{base_url.rstrip('/')}"
        if not url.endswith('/-/reload'):
            url += "/-/reload"
            
        r = requests.post(url, auth=auth, timeout=5)
        if r.status_code == 200:
            logger.info(f"{name} reloaded.")
        else:
            logger.warning(f"Failed to reload {name}: Server returned {r.status_code} - {r.text}")
    except Exception as e:
        logger.warning(f"Failed to reload {name}: {str(e)}")

def main():
    """
    [MCP Entry Point] Agent Lifecycle
    """
    logger.info("Promere Satellite Agent Started (Full Sync + Health)")
    while True:
        success, payload = sync_and_report_health()
        if success and payload:
            prom_changes = False
            am_changes = False
            
            # Sync Targets (JSON) and Rules (YAML)
            if sync_directory(TARGETS_DIR, payload.get('targets', {}), True): prom_changes = True
            if sync_directory(RULES_DIR, payload.get('rules', {}), False): prom_changes = True
            
            # Sync Global Configs (Granular control)
            if SYNC_PROM_CONFIG:
                if sync_single_file(PROM_CONFIG_FILE, payload.get('prometheus_config')): prom_changes = True
            
            if SYNC_AM_CONFIG:
                if sync_single_file(AM_CONFIG_FILE, payload.get('alertmanager_config')): am_changes = True
            
            # Trigger Reloads if needed
            if prom_changes: reload_service(PROMETHEUS_BASE_URL, "Prometheus", PROM_USER, PROM_PASS)
            if am_changes: reload_service(ALERTMANAGER_BASE_URL, "Alertmanager", AM_USER, AM_PASS)
            
        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__": main()