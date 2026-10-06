import http from 'node:http';
import { pathToFileURL } from 'node:url';

export function createCoordinator() {
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Phase 1 deliberately exposes no registration, signaling or control routes.
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200);
      res.end(JSON.stringify({ service: 'wii-ultra-desk-coordinator', status: 'ok',
        phase: 'foundation', remoteSessionsAvailable: false }));
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'not_found' }));
    }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 50;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 4310);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  const server = createCoordinator();
  // Local development only. Add reviewed TLS ingress before public deployment.
  server.listen(port, '127.0.0.1', () => console.log(`Coordinator: http://127.0.0.1:${port}/healthz`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
}
