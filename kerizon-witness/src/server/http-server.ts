import http from 'node:http';
import type { KerizonWitness } from '../witness.js';

export function createWitnessHttpServer(witness: KerizonWitness): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const method = req.method ?? 'GET';

    try {
      // POST / — submit CESR event
      if (method === 'POST' && url.pathname === '/') {
        const body = await readBody(req);
        const result = await witness.processEvent(new Uint8Array(body));

        if ('receipt' in result) {
          res.writeHead(204);
          res.end();
          return;
        }

        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end(result.error);
        return;
      }

      // GET /oobi/{...} — serve witness OOBI
      if (method === 'GET' && url.pathname.startsWith('/oobi/')) {
        const oobiResponse = await witness.getOobiResponse();
        res.writeHead(200, { 'Content-Type': 'application/cesr+json' });
        res.end(oobiResponse);
        return;
      }

      // GET /query?pre={prefix} — KEL query
      if (method === 'GET' && url.pathname === '/query') {
        const prefix = url.searchParams.get('pre');
        if (!prefix) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('missing pre parameter');
          return;
        }

        const kel = await witness.getKel(prefix);
        if (kel) {
          res.writeHead(200, { 'Content-Type': 'application/cesr+json' });
          res.end(kel);
          return;
        }

        res.writeHead(404);
        res.end();
        return;
      }

      // Everything else: 405
      res.writeHead(405);
      res.end();
    } catch (err: unknown) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(err instanceof Error ? err.message : String(err));
    }
  });
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
