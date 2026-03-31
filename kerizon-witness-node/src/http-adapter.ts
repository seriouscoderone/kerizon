import http from 'node:http';
import type { WitnessHandler, TransportServer } from '@kerizon/witness';

export function createHttpServer(handler: WitnessHandler): TransportServer {
  let server: http.Server;

  return {
    async listen(port: number) {
      server = http.createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
        try {
          if (req.method === 'POST' && url.pathname === '/') {
            const body = await readBody(req);
            const result = await handler.handleEventSubmission(new Uint8Array(body));
            res.writeHead(result.status, result.body ? { 'Content-Type': 'text/plain' } : undefined);
            res.end(result.body ?? '');
          } else if (req.method === 'GET' && url.pathname.startsWith('/oobi/')) {
            const result = await handler.handleOobiRequest(url.pathname);
            res.writeHead(result.status, { 'Content-Type': result.contentType, ...result.headers });
            res.end(result.body);
          } else if (req.method === 'GET' && url.pathname === '/query') {
            const prefix = url.searchParams.get('pre');
            if (!prefix) { res.writeHead(400); res.end('missing pre'); return; }
            const result = await handler.handleKelQuery(prefix);
            res.writeHead(result.status, result.body ? { 'Content-Type': 'application/json+cesr' } : undefined);
            res.end(result.body ?? '');
          } else {
            res.writeHead(405);
            res.end();
          }
        } catch (err: unknown) {
          res.writeHead(500);
          res.end(err instanceof Error ? err.message : String(err));
        }
      });
      await new Promise<void>((resolve) => server.listen(port, resolve));
    },
    async stop() {
      await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    },
  };
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
