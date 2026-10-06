#!/bin/bash
# Install the device agent as a launchd LaunchAgent (starts at login, restarts on crash).
# Pair first:  node agent/agent.js pair https://mcp.example.com --device-id my-mac
# Then:        bash deploy/install-macos.sh            (DRY_RUN=1 only writes the plist)
# The agent is copied to ~/.local/share/remote-mcp-agent because launchd cannot read ~/Documents, ~/Desktop, ~/Downloads (TCC).
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:-$(command -v node)}; DST="$HOME/.local/share/remote-mcp-agent"; LABEL=com.selfhost.remote-mcp-agent
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
[ -f "$HOME/.config/remote-mcp/device.json" ] || { echo "no device config; run 'node agent/agent.js pair ...' first"; exit 1; }
mkdir -p "$DST/agent" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
cp agent/*.js "$DST/agent/"; cp package.json package-lock.json "$DST/"
(cd "$DST" && npm install --omit=dev --silent)
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$NODE</string><string>$DST/agent/agent.js</string></array>
  <key>WorkingDirectory</key><string>$DST</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>$(dirname "$NODE"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/remote-mcp-agent.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/remote-mcp-agent.log</string>
</dict></plist>
EOF
plutil -lint "$PLIST"
[ -z "${DRY_RUN:-}" ] || { echo "dry run: wrote $PLIST"; exit 0; }
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "started; log: ~/Library/Logs/remote-mcp-agent.log"
