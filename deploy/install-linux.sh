#!/bin/bash
# Install gateway + agent as systemd *user* services on one Linux host, with freshly generated secrets.
#   PUBLIC_URL=https://mcp.example.com [BIND_HOST=127.0.0.1] [DEVICE_ID=linux-main] bash deploy/install-linux.sh
# Run from the repo checkout located at ~/remote-mcp. Secrets are written to ./secrets (0600), never printed.
set -euo pipefail
: "${PUBLIC_URL:?set PUBLIC_URL, e.g. https://mcp.example.com (the URL clients and devices will use)}"
BIND_HOST=${BIND_HOST:-127.0.0.1}   # 127.0.0.1 when the reverse proxy runs on this host; the LAN IP when it runs elsewhere
DEVICE_ID=${DEVICE_ID:-$(hostname -s | tr 'A-Z' 'a-z')}
cd "$(dirname "$0")/.."
[ "$(id -u)" -ne 0 ] || { echo "do not run as root"; exit 1; }
npm install --omit=dev --silent
umask 077; mkdir -p secrets
A="node --disable-warning=ExperimentalWarning gateway/admin.js"
[ -f secrets/owner-token ] || $A client-create owner --admin | sed -n 's/^client_token: //p' > secrets/owner-token
if [ ! -f secrets/device-secret ]; then
  $A device-create "$DEVICE_ID" | sed -n 's/^device_secret: //p' > secrets/device-secret
  node agent/agent.js init --gateway "${PUBLIC_URL/https:/wss:}/device" --device-id "$DEVICE_ID" --secret "$(cat secrets/device-secret)"
fi
mkdir -p ~/.config/systemd/user
for u in gateway agent; do
  sed -e "s#@BIND_HOST@#$BIND_HOST#g" -e "s#@PUBLIC_URL@#$PUBLIC_URL#g" "deploy/remote-mcp-$u.service.in" > ~/.config/systemd/user/remote-mcp-$u.service
done
systemctl --user daemon-reload
systemctl --user enable --now remote-mcp-gateway remote-mcp-agent
loginctl enable-linger "$USER" || echo "note: could not enable linger; services stop when you log out"
echo "installed. Owner token (needed once to approve OAuth clients): ~/remote-mcp/secrets/owner-token"
