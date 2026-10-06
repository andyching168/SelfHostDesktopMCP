#!/bin/bash
# Update a deployed checkout from GitHub and restart whatever is installed here (systemd user units or the macOS LaunchAgent).
# Fast-forward only: refuses to run over local edits instead of clobbering them.
set -euo pipefail
cd "$(dirname "$0")/.."
git fetch -q origin
BEFORE=$(git rev-parse --short HEAD)
git pull --ff-only -q origin "$(git rev-parse --abbrev-ref HEAD)"
AFTER=$(git rev-parse --short HEAD)
[ "$BEFORE" != "$AFTER" ] && git log --oneline "$BEFORE..$AFTER" || echo "already up to date ($AFTER)"
npm ci --omit=dev --silent
if [ "$(uname)" = Darwin ]; then
  L=com.selfhost.remote-mcp-agent
  if launchctl print "gui/$(id -u)/$L" >/dev/null 2>&1; then launchctl kickstart -k "gui/$(id -u)/$L" && echo "restarted $L"; fi
else
  for u in remote-mcp-gateway remote-mcp-agent; do
    if systemctl --user is-enabled "$u" >/dev/null 2>&1; then systemctl --user restart "$u" && echo "restarted $u"; fi
  done
fi
