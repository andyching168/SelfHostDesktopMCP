# Security notes

## Model
- The agent runs tools as the **OS user that started it**. Run it as a normal user (it refuses root), ideally a dedicated low-privilege account or container for anything you do not fully trust the caller with.
- The **gateway is trusted infrastructure**: it sees and can alter all traffic. Keep it on hardware you control.
- Prompt injection is not solved by authentication. A model reading a hostile web page can call your tools. Use least privilege, the policy layer, and review the audit log.

## What is protected
| Asset | Handling |
|---|---|
| Client / device secrets | 256-bit random, only SHA-256 stored, constant-time compare, shown once |
| OAuth | PKCE S256 only, exact redirect_uri match, codes single-use (5 min), access 1 h, refresh rotated, consent requires an admin token (5 failures / min global limiter) |
| Pairing | endpoints 404 unless a window is open (default 3 min, CLI only); secret generated at collection time and returned once; existing device ids cannot be re-paired |
| Management API `/api/*` | admin token; additionally answers 404 to anything that came through a reverse proxy (`X-Forwarded-For`/`X-Real-IP`) |
| Web console `/admin` | TOTP-only login (RFC 6238), global lockout 5 failures/15 min, one-time use per time step, HttpOnly + SameSite=Strict + Secure cookie, CSRF token + Origin check on every write, strict CSP (no inline script, no third-party resources), UI renders data via `textContent` only. Enrolment page exists only until enabled and needs the owner token. |
| Audit log | metadata only; arguments, file contents and output are never stored |

## Policy layer (agent side)
Blocks sensitive paths (`~/.ssh`, `~/.gnupg`, cloud credentials, the agent's own config/secrets), makes the agent's own code read-only, denies
`sudo`, shutdown/reboot, `rm -rf /`-style commands, pipe-to-shell, and disables the backend's `set_config_value`.
**It is a guardrail.** A caller with a shell can obfuscate commands (encoding, indirection, scripts) and defeat string matching. Real isolation needs a separate OS user, container or VM.

## Web console caveats
- TOTP is a single factor (something you have). Anyone holding the TOTP seed or your unlocked phone can sign in; the console can revoke devices and approve pairings. Keep the seed out of screenshots and chats.
- The console is reachable from the internet through your proxy by design. If you do not need it remotely, block `/admin*` at the proxy and use it over a VPN/LAN.

## Operating tips
- Expose only 443 through a TLS reverse proxy; bind the gateway to localhost (or a LAN address only the proxy can reach). Never expose the backend MCP server or the agent.
- Plain `http://` is for localhost, LAN or VPN only.
- Test internet access from outside your own network/VPN, otherwise you only proved the private path.
- Rotate by revoking: `client-revoke`, `device-revoke`; OAuth grants: `UPDATE oauth_tokens SET revoked_at = datetime('now') WHERE revoked_at IS NULL;`.
- Back up the SQLite file if you care about registered devices/clients; it contains hashes, not secrets.

## Reporting
Open a GitHub issue for non-sensitive problems; for vulnerabilities use GitHub's private security advisory on this repository.
