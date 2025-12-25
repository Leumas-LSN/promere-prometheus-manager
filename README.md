# ⚡ Promere: The Missing UI for Prometheus

![Promere Status](https://img.shields.io/badge/Status-Beta-orange?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**Promere** (Prometheus Manager) is a modern, lightweight, and visual interface designed to simplify the management of your Prometheus ecosystem. Stop editing YAML files manually and start managing your monitoring infrastructure like a pro.

---

## 🌟 Why Promere?

Promere solves the complexity of managing Prometheus targets, alert rules, and alertmanager configurations across multiple environments.

### Key Features

*   **🗺️ Visual Topology**: Visualize your entire infrastructure (servers, containers, networks) in an interactive real-time map.
*   **📡 Distributed Architecture**: Manage multiple sites (Satellites) from a single Central Dashboard. No VPN required (Pull-model agents).
*   **📝 No-Code Editors**:
    *   **Target Management**: Add/Edit/Delete scrape targets without touching `prometheus.yml`.
    *   **Visual Rule Builder**: Create Alerting Rules using a UI builder (no PromQL knowledge required).
    *   **Alertmanager**: Configure receivers (Email, Slack, Discord) and routing trees visually.
*   **🛡️ Secure by Design**: Role-Based Access Control (RBAC), API Key management, and self-signed SSL out-of-the-box.
*   **⚡ Command Palette**: Navigate and control everything with `Ctrl + J`.

---

## 🚀 Quick Start (Central Server)

Deploy the **Promere Central** server. This is the brain of your monitoring operations.
The central server requires access to your Prometheus and Alertmanager configuration files to manage them.

### `docker-compose.yml`

```yaml
version: "3.8"

services:
  promere:
    image: ghcr.io/leumas-lsn/promere:latest
    container_name: promere
    restart: unless-stopped
    ports:
      - "8090:8090" # HTTP Redirector
      - "8091:8091" # HTTPS UI & API
    environment:
      # Secrets (Change these!)
      - ADMIN_PASSWORD=admin
      - SECRET_KEY=change_me_to_something_secure_and_long
      
      # Configuration Paths (Inside container)
      # These tell Promere where to look for your Prometheus/Alertmanager files
      - PROMETHEUS_YML_PATH=/config/prometheus.yml
      - ALERTMANAGER_YML_PATH=/config/alertmanager/alertmanager.yml

    volumes:
      # [Persistence] App State & Certs
      - ./promere_data/config:/app/config
      - ./promere_data/certs:/app/certs
      
      # [Integration] Prometheus Targets (Shared with Prometheus)
      # Promere writes JSON files here. Prometheus must read them via 'file_sd_configs'.
      - ./monitoring/targets:/app/targets

      # [Integration] Alert Rules (Shared with Prometheus)
      # Promere writes YAML rule files here.
      - ./monitoring/rules:/app/rules

      # [Integration] Prometheus Config (Read-Only)
      # Promere reads this to discover "Jobs" and display them in the UI.
      - ./monitoring/prometheus.yml:/config/prometheus.yml:ro

      # [Integration] Alertmanager Config (Read/Write)
      # Promere rewrites this file to manage receivers/routes.
      - ./monitoring/alertmanager:/config/alertmanager
```

---

## 📡 Adding a Remote Site (Satellite)

To monitor a remote infrastructure (behind NAT or Firewall), deploy a **Satellite**. It connects back to your Central server to sync configurations.

1.  Go to **Settings > API Access** on your Central server and generate a new **API Key**.
2.  Deploy the satellite on the remote network:

### `docker-compose-satellite.yml`

```yaml
version: "3.8"

services:
  promere-satellite:
    image: ghcr.io/leumas-lsn/promere-satellite:latest
    container_name: promere-satellite
    restart: always
    network_mode: host  # Recommended to reach local Prometheus/Exporters easily
    
    environment:
      # [Connection to Central]
      - CENTRAL_URL=https://<YOUR_CENTRAL_IP>:8091
      - API_KEY=<YOUR_API_KEY_HERE>
      - VERIFY_SSL=false # Set to true if Central has a valid CA certificate
      - SYNC_INTERVAL=60
      
      # [Local Integration]
      # Where are your local services running?
      - PROMETHEUS_BASE_URL=http://localhost:9090
      - ALERTMANAGER_BASE_URL=http://localhost:9093
      
      # [Sync Configuration]
      # What should this satellite manage?
      - SYNC_TARGETS=true
      - SYNC_RULES=true
      - SYNC_AM_CONFIG=true
      
      # [File Paths] (Inside Container)
      - TARGETS_DIR=/etc/prometheus/targets
      - RULES_DIR=/etc/prometheus/rules
      - AM_CONFIG_FILE=/etc/alertmanager/alertmanager.yml

    volumes:
      # [Shared Volumes]
      # Mount the directories where your local Prometheus reads config from.
      - /etc/prometheus/targets:/etc/prometheus/targets
      - /etc/prometheus/rules:/etc/prometheus/rules
      - /etc/alertmanager:/etc/alertmanager
```

---

## 🛠️ Development

This is a Monorepo containing:
*   `new_ui/`: The Flask-based Central Application.
*   `new_ui/satellite_agent/`: The Python-based Satellite Agent.

### Tech Stack
*   **Backend:** Python 3.11, Flask, Jinja2.
*   **Frontend:** Alpine.js, TailwindCSS, Vis.js (Topology).
*   **Data:** JSON-based persistence (No external DB required).

---

## 📜 License

MIT License. Free to use and modify.
