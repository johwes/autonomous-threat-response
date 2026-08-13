# Build the autonomous threat response agent container.
# Base: Red Hat UBI9 Python 3.11 — compatible with OpenShift / RHEL ecosystems.
#
# Build:
#   podman build -t threat-response-agent:latest .
#
# Run locally (dev):
#   podman run --rm -p 8080:8080 \
#     -e OPENAI_API_KEY=sk-... \
#     -e AAP_MCP_URL=https://... \
#     -e AAP_TOKEN=... \
#     threat-response-agent:latest

FROM registry.access.redhat.com/ubi9/python-311:latest

WORKDIR /app

# Install Python dependencies before copying app code (layer cache)
# Use --chown so OpenShift's arbitrary UID (in root group) can read the files
COPY --chown=1001:0 agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source with correct ownership
COPY --chown=1001:0 agent/ .

# Make group-writable for OpenShift's arbitrary non-root UID policy
RUN chmod -R g=u /app

USER 1001

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
