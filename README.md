# SelfHostDesktopMCP

A self-hosted **remote MCP gateway**: let MCP clients (ChatGPT connectors, Claude, Hermes, …) use tools on your own machines
without handing a third party the relay, the accounts or the logs.

```
MCP client ──HTTPS /mcp──▶ gateway ◀──WSS /device── agent ──stdio──▶ local MCP server (e.g. Desktop Commander)
```

- Devices only make **outbound** connections. No inbound ports on your laptops, and the local MCP server is never exposed.
- One gateway, many devices (Linux, macOS, …). The gateway is not coupled to Desktop Commander; any stdio MCP server can be the backend.
- Node ≥ 22.13, two runtime dependencies (`ws`, `@modelcontextprotocol/sdk`), SQLite via the built-in `node:sqlite`.

> ⚠️ A device agent can do whatever its OS user can do. Authentication is not a sandbox. Read [docs/SECURITY.md](docs/SECURITY.md) before exposing anything.

## Features
- **MCP Streamable HTTP** at `/mcp` (JSON responses), tool calls relayed to the chosen device; per-device tool lists.
- **Auth**: static bearer tokens for clients; **OAuth 2.1** (dynamic client registration, PKCE S256, refresh rotation, RFC 8414/9728 metadata) for connectors such as ChatGPT. Consent needs an admin ("owner") token.
- **Web admin console** at `/admin/` (mobile-friendly): devices, clients/OAuth grants, activity log, pairing approval. Sign-in is **TOTP only** (any authenticator app), enrolled by scanning a QR in your own browser.
- **MCP servers per device, managed in the console**: pick a template (Chrome DevTools, Playwright) or, if the device opted in, a custom command; per-tool on/off switches; tools appear as `prefix_toolname` next to the built-in Desktop Commander tools.
- **Per-device secrets**, stored only as SHA-256 hashes; instant revocation (live connection is dropped).
- **Pairing**: `/pair/*` does not exist until you open a 3-minute window from the CLI; approve the request in the terminal.
- **Routing that works with stateless clients**: pass `device_id` on any call; `device_select` sets a per-client default.
- **Device-side policy** (guardrail): blocked paths (symlink-aware), read-only paths, blocked commands/patterns, disabled tools.
- **Audit log** (SQLite): client, device, tool, request id, duration, status — never arguments or output.
- Keepalive (20 s ping / 60 s timeout), 30 s call timeout, explicit `DEVICE_OFFLINE`, auto-reconnect with backoff.

## Quick start (one machine, localhost)
```bash
npm install
node gateway/admin.js client-create me                 # prints a client token once
node gateway/admin.js device-create my-box             # prints a device secret once
node agent/agent.js init --gateway ws://127.0.0.1:8765/device --device-id my-box --secret <device-secret>
node gateway/server.js                                  # 127.0.0.1:8765
node agent/agent.js                                     # spawns Desktop Commander over stdio (use --mock to try without it)
RMCP_URL=http://127.0.0.1:8765 RMCP_TOKEN=<client-token> node test/smoke.js my-box
npm test
```
Gateway flags / env: `--host`, `--port`, `--db`, `--public-url` (issuer for OAuth; required behind a proxy), `--call-timeout`, `--offline-timeout`
(or `RMCP_HOST`, `RMCP_PORT`, `RMCP_DB`, `RMCP_PUBLIC_URL`, …).

## Going public
1. Put a TLS reverse proxy in front (443 only), forward `/mcp`, `/device`, `/health`, `/.well-known/*`, `/authorize`, `/token`, `/register`, `/pair/*` to the gateway. WebSocket support must be on, no proxy-level basic auth. See [docs/reverse-proxy.md](docs/reverse-proxy.md).
2. Linux host: `PUBLIC_URL=https://mcp.example.com bash deploy/install-linux.sh` (systemd user units, fresh secrets in `./secrets`).
3. Test **from a network outside your LAN/VPN**: `curl https://mcp.example.com/health`, then `test/smoke.js`.
4. If your ISP uses CGNAT you cannot port-forward; run the gateway on a VPS instead (devices connect outbound to it).

### Connect clients
- **ChatGPT / OAuth clients**: add `https://mcp.example.com/mcp` as a custom MCP server with OAuth. Approve on the consent page with the owner token (`secrets/owner-token`).
- **Static token clients**: `Authorization: Bearer <token>` from `admin.js client-create <name>`.
- Always pass `device_id` in tool arguments (some clients open a new MCP session per call).

### Add a device (pairing)
```bash
# on the gateway host: opens a 3-minute window, shows requests, asks for approval
node gateway/admin.js pair
# on the new machine (checkout + npm install):
node agent/agent.js pair https://mcp.example.com --device-id my-laptop
#   compare the code shown on both sides, answer y on the gateway
node agent/agent.js            # or: bash deploy/install-macos.sh  (LaunchAgent) / deploy/*.service.in (systemd)
```

### Web console and two-step login
1. Open `https://mcp.example.com/admin/setup` (only exists until two-step login is enabled), enter the owner token (`secrets/owner-token`).
2. Scan the QR with an authenticator app, type the 6-digit code to confirm. The secret is shown once and never leaves your browser/phone.
3. Sign in at `/admin/` with a code from the app. Lost the phone: `node gateway/admin.js totp-reset` on the gateway host, then enrol again.

Sign-in locks for 15 minutes after 5 wrong codes, a code can be used once, sessions expire after 30 min idle / 12 h, writes need a CSRF token.

### Tool exposure (for clients that never refresh their tool list)
Some MCP clients (e.g. Hermes) call `tools/list` once and never again, so the list must not depend on runtime state. By default (per-client *fixed* mode):
- `tools/list` = `devices_list`, `device_select`, `tools_list`, `tool_call` + the built-in Desktop Commander tools (a snapshot stored on the gateway, so it is identical whether or not a device is online or selected).
- Tools of servers added in the console (`chrome_*`, custom) are **not** listed. The model discovers them with `tools_list` and runs them with `tool_call {name, arguments, device_id}`; they work the moment they are added, with no reconnect. Audit records the inner tool name.
- Clients that do refresh can be switched to *live* mode in the console (Clients tab), where `tools/list` shows everything the selected device exposes right now. `?tools=all|stable` on the MCP URL overrides the setting per connection.

### Adding MCP servers to a device
Console → Devices → *MCP servers* → *Add an MCP server*. The gateway stores the list and pushes it to the agent whenever it connects or you change it.
- **Templates** (`agent/backends.js`) are chosen by the agent: the console sends only `{template, params}`, so it cannot inject flags like `--executablePath`. Risky tools (`evaluate_script`, `upload_file`, …) start disabled; tick them on per tool.
- **Custom command** runs any command as the device's user and is **off by default**. Enable it on a device you control by adding `{"allow_custom_backends": true}` to that device's `~/.config/remote-mcp/policy.json`.
- The device policy (blocked paths, `file:` URLs, …) applies to every added server's tools too. Packages are fetched with `npx -y <pkg>@latest`; pin a version via a custom command if you need to.
- A failing server shows its error in the console and does not affect the others.

### Revoke
```bash
node gateway/admin.js client-revoke <client_id>     # static client token
node gateway/admin.js device-revoke <device_id>     # device; a live agent is dropped and exits
node gateway/admin.js list
```
OAuth grants live in `oauth_tokens`; revoke by setting `revoked_at` (see docs/SECURITY.md). If the owner token leaks: revoke it and create a new one.

### Update
`bash deploy/update.sh` on any deployed host: `git pull --ff-only`, `npm install`, restarts the systemd units / LaunchAgent that are installed there.

## Layout
```
gateway/   server.js (HTTP/MCP/WS)  oauth.js  pairing.js  web.js + ui/ (admin console)  totp.js  db.js  admin.js (offline CLI)
agent/     agent.js (device side)   policy.js (guardrails)   backends.js (MCP server templates)
deploy/    install-linux.sh  install-macos.sh  update.sh  *.service.in
test/      e2e, OAuth, pairing and policy tests (node --test)
```

## Policy
`~/.config/remote-mcp/policy.json` **extends** the defaults in `agent/policy.js`:
```json
{ "blocked_paths": ["~/Library/Keychains"], "readonly_paths": ["~/src/this-repo"], "allowed_paths": [], "blocked_commands": ["curl"] }
```
Set `"replace_defaults": true` to replace instead of extend. It is a guardrail, not a security boundary.

## Limits / not done
Single gateway instance (no HA), SQLite only, no per-operation human approval, OAuth is single-owner, Windows has no service installer.

## License
MIT — see [LICENSE](LICENSE). Provided as is; running an agent that executes commands on your machine is your responsibility (see docs/SECURITY.md).
