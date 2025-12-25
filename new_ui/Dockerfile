# [MCP Context] Build Instructions
# Base image: Python 3.11 Slim (Debian based) for small footprint.
# Security: Now includes SSL certificate generation and bcrypt authentication.

FROM python:3.11-slim

# [MCP Workspace]
WORKDIR /app

# [MCP Dependencies] Install from requirements.txt
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# [MCP Code] Copy application source
COPY app.py /app/
COPY ssl_utils.py /app/
COPY start.py /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

# [MCP Volumes Preparation]
# Ensure directories exist for volume mounts and certificates
RUN mkdir -p /app/targets /app/certs /app/config /config

# Make start script executable
RUN chmod +x /app/start.py

# [MCP Network] Expose HTTPS port
EXPOSE 8443

# [MCP Entrypoint] Start with SSL certificate generation
CMD ["python3", "/app/start.py"]