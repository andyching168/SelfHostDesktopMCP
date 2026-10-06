// Guardrail policy evaluated on the device before any tool call reaches the local MCP server.
// NOT a security boundary: a determined caller with shell access can obfuscate commands.
// It stops accidents, careless prompt-injected requests, and the obvious secret locations.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const home = os.homedir();
const DEFAULTS = {
  // no read, write, list or search of these (prefix match, symlinks resolved)
  blocked_paths: ['~/.ssh', '~/.gnupg', '~/.aws', '~/.kube', '~/.netrc', '~/.config/gcloud', '~/.config/remote-mcp', '~/remote-mcp/secrets', '~/remote-mcp/remote-mcp.db'],
  // readable, but no writes / moves (keeps the agent, gateway and service files tamper-resistant)
  readonly_paths: ['~/remote-mcp', '~/.config/systemd', '~/.bashrc', '~/.profile', '~/.zshrc'],
  // if non-empty, every path must be inside one of these
  allowed_paths: [],
  blocked_commands: ['shutdown', 'reboot', 'poweroff', 'halt', 'init', 'mkfs', 'fdisk', 'parted', 'wipefs', 'sudo', 'su', 'doas', 'passwd', 'visudo', 'crontab', 'iptables', 'nft', 'ufw', 'tailscale'],
  blocked_patterns: ['rm\\s+(-\\w*\\s+)*-\\w*[rf]\\w*\\s+(--no-preserve-root\\s+)?(/|~|\\$HOME)(\\s|/?$)', 'dd\\s+.*of=/dev/', '>\\s*/dev/(sd|nvme|disk)', ':\\(\\)\\s*\\{', 'chmod\\s+(-\\w+\\s+)*[0-7]*777\\s+/(\\s|$)', 'systemctl\\s+(--user\\s+)?(stop|disable|mask|kill)\\s+remote-mcp', 'curl[^|]*\\|\\s*(ba|z)?sh', 'wget[^|]*\\|\\s*(ba|z)?sh'],
  blocked_tools: ['set_config_value'], // DC's own config (allowedDirectories, blockedCommands) must not be rewritten remotely
};
const WRITE_TOOLS = new Set(['write_file', 'write_pdf', 'edit_block', 'create_directory', 'move_file']);
const PATH_KEYS = /^(path|paths|file_path|filepath|source|destination|dest|directory|dir|cwd|working_directory|output_path|outputpath)$/i;
const CASE = process.platform === 'linux' ? (s) => s : (s) => s.toLowerCase();

const expand = (p) => (p === '~' ? home : p.startsWith('~/') ? path.join(home, p.slice(2)) : p);
function real(p) {
  // realpath of the deepest existing ancestor + remaining tail, so not-yet-existing targets still resolve
  let abs = path.resolve(home, expand(p)), tail = '';
  for (;;) {
    try { return CASE(path.join(fs.realpathSync(abs), tail)); } catch {
      const parent = path.dirname(abs);
      if (parent === abs) return CASE(abs);
      tail = path.join(path.basename(abs), tail); abs = parent;
    }
  }
}
const inside = (child, root) => child === root || child.startsWith(root.endsWith(path.sep) ? root : root + path.sep);

export function loadPolicy(file) {
  let user = {};
  try { user = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw new Error(`bad policy file ${file}: ${e.message}`); }
  // user lists extend the defaults, never silently replace them; set "replace_defaults": true to opt out
  const merge = (k) => (user.replace_defaults ? user[k] ?? [] : [...DEFAULTS[k], ...(user[k] ?? [])]);
  const p = Object.fromEntries(Object.keys(DEFAULTS).map((k) => [k, merge(k)]));
  return {
    ...p,
    blockedReal: p.blocked_paths.map((x) => ({ raw: x, abs: real(x) })),
    readonlyReal: p.readonly_paths.map((x) => ({ raw: x, abs: real(x) })),
    allowedReal: p.allowed_paths.map(real),
    allow_custom_backends: user.allow_custom_backends === true,
    patterns: p.blocked_patterns.map((x) => new RegExp(x, 'i')),
    cmdRe: new RegExp(`(^|[^\\w.-])(${p.blocked_commands.map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?![\\w-])`, 'i'),
  };
}

const collect = (v, out) => { if (typeof v === 'string') out.push(v); else if (Array.isArray(v)) v.forEach((x) => collect(x, out)); };

/** Returns null if allowed, otherwise a human-readable denial reason. */
export function check(policy, tool, args = {}) {
  if (policy.blocked_tools.includes(tool)) return `tool ${tool} is disabled by policy`;

  const paths = [];
  for (const [k, v] of Object.entries(args)) if (PATH_KEYS.test(k)) collect(v, paths);
  const write = WRITE_TOOLS.has(tool);
  for (const raw of paths) {
    const abs = real(raw);
    const b = policy.blockedReal.find((x) => inside(abs, x.abs)); if (b) return `path ${raw} is inside blocked location ${b.raw}`;
    if (write) { const r = policy.readonlyReal.find((x) => inside(abs, x.abs)); if (r) return `path ${raw} is read-only (${r.raw})`; }
    if (policy.allowedReal.length && !policy.allowedReal.some((a) => inside(abs, a))) return `path ${raw} is outside allowed_paths`;
  }

  for (const [k, v] of Object.entries(args)) // a browser tool must not be a way around the path rules
    if (/^url$/i.test(k) && typeof v === 'string' && /^\s*(file|javascript|chrome|chrome-extension|view-source):/i.test(v)) return `${k} uses a blocked scheme`;

  const cmd = tool === 'start_process' ? args.command : tool === 'interact_with_process' ? args.input : null;
  if (typeof cmd === 'string') {
    const m = policy.cmdRe.exec(cmd); if (m) return `command contains blocked program "${m[2]}"`;
    const pat = policy.patterns.find((re) => re.test(cmd)); if (pat) return 'command matches a blocked pattern';
    // blocked locations mentioned textually (also $HOME / ~ forms)
    const text = cmd.replace(/\$\{?HOME\}?/g, home).replace(/(^|[\s'"=:])~(?=\/|\s|$|'|")/g, `$1${home}`);
    for (const b of policy.blockedReal) {
      const plain = b.abs;
      if (CASE(text).includes(plain) || CASE(text).includes(CASE(path.join(home, path.relative(home, plain))))) return `command references blocked location ${b.raw}`;
    }
  }
  return null;
}
