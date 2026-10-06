// Tiny stdio MCP server used by tests as a "custom backend".
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'mock', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: 'ping2', description: 'Returns pong2:<text>', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } },
  { name: 'read_path', description: 'Pretends to read a path', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  { name: 'dangerous', description: 'Disabled by default in templates, here enabled', inputSchema: { type: 'object' } },
] }));
server.setRequestHandler(CallToolRequestSchema, async (req) => ({ content: [{ type: 'text', text: req.params.name === 'ping2' ? `pong2:${req.params.arguments?.text ?? ''}` : `ran ${req.params.name}` }] }));
await server.connect(new StdioServerTransport());
