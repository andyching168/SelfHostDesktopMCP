// Usage: RMCP_URL=http://host:8765 RMCP_TOKEN=... node test/smoke.js [device_id] [file]
// Works from any machine (Node >= 18). Exercises initialize → tools/list → read_file/list_directory/start_process.
const base = process.env.RMCP_URL, token = process.env.RMCP_TOKEN;
const [device = 'linux-main', file = '/tmp/remote-mcp-test.txt'] = process.argv.slice(2);
let sid, n = 0;
async function rpc(method, params) {
  const r = await fetch(`${base}/mcp`, { method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}`, ...(sid ? { 'mcp-session-id': sid } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++n, method, params }) });
  sid ??= r.headers.get('mcp-session-id');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const b = await r.json(); if (b.error) throw new Error(JSON.stringify(b.error)); return b.result;
}
const text = (r) => r.content?.map((c) => c.text).join('\n') ?? JSON.stringify(r);
console.log('health   ', JSON.stringify(await (await fetch(`${base}/health`)).json()));
await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } });
console.log('tools    ', (await rpc('tools/list')).tools.map((t) => t.name).join(', '));
console.log('select   ', text(await rpc('tools/call', { name: 'device_select', arguments: { device_id: device } })));
console.log('read_file', text(await rpc('tools/call', { name: 'read_file', arguments: { path: file } })).slice(0, 200));
console.log('list_dir ', text(await rpc('tools/call', { name: 'list_directory', arguments: { path: '/tmp' } })).split('\n').length, 'lines');
const p = await rpc('tools/call', { name: 'start_process', arguments: { command: 'echo remote-ok && uname -n', timeout_ms: 5000 } });
console.log('start_process', p.isError ? 'ERROR' : '', text(p).slice(0, 200));
