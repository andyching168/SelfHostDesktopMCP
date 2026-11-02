// Tiny Streamable-HTTP MCP server used by tests as a "remote" backend. Usage: node mock-http-mcp.js PORT [TOKEN]
import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const [port, token] = [Number(process.argv[2]), process.argv[3]];
http.createServer(async (req, res) => {
  if (token && req.headers.authorization !== `Bearer ${token}`) { res.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"unauthorized"}'); return; }
  const server = new Server({ name: 'mock-http', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'hello', description: 'Returns hello:<text>', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } }] }));
  server.setRequestHandler(CallToolRequestSchema, async (r) => ({ content: [{ type: 'text', text: `hello:${r.params.arguments?.text ?? ''}` }] }));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close(); server.close(); });
  await server.connect(transport);
  let body = ''; for await (const c of req) body += c;
  await transport.handleRequest(req, res, body ? JSON.parse(body) : undefined);
}).listen(port, '127.0.0.1');
