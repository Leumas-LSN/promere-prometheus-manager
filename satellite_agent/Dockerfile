# [MCP Context] Satellite Agent Build
# Base: Alpine Linux for minimal size (Agent is lightweight).

FROM python:3.11-alpine

WORKDIR /app

# [MCP Dependencies]
# requests: For HTTP communication with Central and Local Services
# pyyaml: For parsing local prometheus.yml
RUN pip install --no-cache-dir requests pyyaml

# [MCP Code]
COPY agent.py .

# [MCP Entrypoint]
# -u: Unbuffered stdout for real-time logging in Docker
CMD ["python", "-u", "agent.py"]