// Catalog of MCP servers the gateway console may ask an agent to run. The agent is the authority:
// the console sends only {template, params}; packages and flags come from this file, so a compromised
// console cannot turn into arbitrary command execution. "custom" commands need an explicit local opt-in
// (allow_custom_backends in the device's own policy.json, which remote tools cannot write).
export const CATALOG = {
  'chrome-devtools': {
    title: 'Chrome DevTools',
    description: 'Drive and inspect Chrome: pages, DOM snapshots, screenshots, network, console. By default it launches a throw-away profile; with autoConnect it attaches to the Chrome you are already running.',
    package: 'chrome-devtools-mcp', prefix: 'chrome_',
    params: [
      { key: 'autoConnect', label: 'Use my running Chrome (--autoConnect): your real profile and logged-in sessions', type: 'boolean', default: false },
      { key: 'headless', label: 'Headless (no visible window; ignored with autoConnect)', type: 'boolean', default: false },
    ],
    // --autoConnect attaches to an existing browser, so it replaces --isolated/--headless (which only apply to a browser it launches itself)
    args: (p) => (p.autoConnect ? ['--autoConnect'] : ['--isolated', ...(p.headless ? ['--headless'] : [])]),
    default_disabled: ['evaluate_script', 'upload_file'], // arbitrary JS in the page / reading local files into a page
  },
  playwright: {
    title: 'Playwright browser',
    description: 'Browser automation by accessibility snapshot (navigate, click, type, screenshot). In-memory profile.',
    package: '@playwright/mcp', prefix: 'playwright_',
    params: [{ key: 'headless', label: 'Headless (no visible window)', type: 'boolean', default: false }],
    args: (p) => ['--isolated', ...(p.headless ? ['--headless'] : [])],
    default_disabled: ['browser_evaluate', 'browser_run_code', 'browser_file_upload'],
  },
};
export const NAME_RE = /^[a-z][a-z0-9-]{1,30}$/;
export const REMOTE_AUTH = ['none', 'token', 'oauth'];

/** Validate the params of a "remote" (HTTP URL) server; shared by the console and the agent. Returns an error string or null. */
export function checkRemoteParams(p) {
  let u; try { u = new URL(p.url); } catch { return 'url: not a valid URL'; }
  if (!/^https?:$/.test(u.protocol) || p.url.length > 500) return 'url must be http(s)://...';
  const auth = p.auth ?? 'none';
  if (!REMOTE_AUTH.includes(auth)) return 'auth must be none, token or oauth';
  const str = (k, max, req) => (typeof p[k] === 'string' && p[k].length <= max && (!req || p[k].trim() !== '')) || (!req && (p[k] === undefined || p[k] === ''));
  if (auth === 'token' && !str('token', 2000, true)) return 'token required';
  if (auth === 'oauth') {
    if (!str('client_id', 300, true) || !str('client_secret', 2000, true)) return 'OAuth needs client_id and client_secret';
    if (!str('scope', 300, false)) return 'scope must be a string';
  }
  return null;
}

/** Turn a desired entry from the gateway into a command line, or throw with a reason shown in the console. */
export function resolveBackend(spec, policy) {
  const { template, name = template, params = {} } = spec;
  if (template === 'custom') {
    if (!policy?.allow_custom_backends) throw new Error('custom MCP servers are disabled on this device (set allow_custom_backends in its local policy.json)');
    if (!NAME_RE.test(name) || name === 'custom') throw new Error('invalid name');
    const { command, args = [] } = params;
    if (typeof command !== 'string' || !command || command.length > 200) throw new Error('command required');
    if (!Array.isArray(args) || args.length > 20 || !args.every((a) => typeof a === 'string' && a.length <= 300)) throw new Error('args must be up to 20 strings');
    return { name, command: [command, ...args], prefix: `${name.replace(/-/g, '_')}_`, defaultDisabled: [] };
  }
  if (template === 'remote') {
    if (!policy?.allow_custom_backends) throw new Error('remote MCP servers are disabled on this device (set allow_custom_backends in its local policy.json)');
    if (!NAME_RE.test(name) || ['custom', 'remote', 'desktop-commander'].includes(name)) throw new Error('invalid name');
    const bad = checkRemoteParams(params); if (bad) throw new Error(bad);
    return { name, remote: params, prefix: `${name.replace(/-/g, '_')}_`, defaultDisabled: [] };
  }
  const t = CATALOG[template];
  if (!t) throw new Error(`unknown template ${String(template).slice(0, 40)}`);
  if (name !== template) throw new Error('catalog servers use their template id as name');
  const p = {};
  for (const d of t.params) {
    const v = params[d.key] ?? d.default;
    if (d.type === 'boolean' && typeof v !== 'boolean') throw new Error(`${d.key} must be true or false`);
    p[d.key] = v;
  }
  return { name, command: ['npx', '-y', `${t.package}@latest`, ...t.args(p)], prefix: t.prefix, defaultDisabled: t.default_disabled };
}
