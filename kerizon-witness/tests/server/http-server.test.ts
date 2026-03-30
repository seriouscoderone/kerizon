import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { createWitnessHttpServer } from '../../src/server/http-server.js';
import { KerizonWitness } from '../../src/witness.js';
import { NedbStore } from '../../src/store/nedb-store.js';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Signer, Siger, Serder, CtrDex_1_0, b64Index } from '@kerizon/cesr';
import { incept } from '@kerizon/keri-core';

function httpGet(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode!, body }));
    }).on('error', reject);
  });
}

function httpPost(
  url: string,
  data: Buffer,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST' },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode!, body }));
      },
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function encodeCounter(code: string, count: number): string {
  return (
    code +
    b64Index(Math.floor(count / 64) & 0x3f) +
    b64Index(count & 0x3f)
  );
}

function buildCesr(serder: Serder, sigers: Siger[]): Uint8Array {
  const jsonPart = new TextDecoder().decode(serder.raw);
  const totalQuadlets = sigers.reduce((sum, s) => sum + s.qb64.length / 4, 0);
  const counter = encodeCounter(CtrDex_1_0.ControllerIdxSigs, totalQuadlets);
  const sigsPart = sigers.map((s) => s.qb64).join('');
  const full = jsonPart + counter + sigsPart;
  return new TextEncoder().encode(full);
}

describe('HTTP server', () => {
  let dbDir: string;
  let store: NedbStore;
  let witness: KerizonWitness;
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    dbDir = await mkdtemp(join(tmpdir(), 'witness-http-test-'));
    store = new NedbStore(dbDir);
    witness = await KerizonWitness.create(
      { name: 'wit-http', httpPort: 0, tcpPort: 0 },
      store,
    );
    server = createWitnessHttpServer(witness);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address() as { port: number };
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await store.close();
    await rm(dbDir, { recursive: true, force: true });
  });

  it('GET /oobi/anything returns 200 with CESR body containing version string', async () => {
    const res = await httpGet(`${baseUrl}/oobi/anything`);
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);
    // The body is the witness inception JSON which has a "v" field
    const parsed = JSON.parse(res.body);
    expect(parsed.v).toBeDefined();
    expect(parsed.t).toBe('icp');
  });

  it('POST / with valid CESR inception returns 204', async () => {
    const ctrlSigner = await Signer.generate();
    const ctrlSerder = incept({
      keys: [ctrlSigner.verfer.qb64],
      nextDigests: [],
      nextThreshold: '0',
    });
    const sigRaw = await ctrlSigner.sign(ctrlSerder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });
    const cesr = buildCesr(ctrlSerder, [siger]);

    const res = await httpPost(`${baseUrl}/`, Buffer.from(cesr));
    expect(res.status).toBe(204);
  });

  it('POST / with garbage returns 400', async () => {
    const res = await httpPost(`${baseUrl}/`, Buffer.from('not valid cesr'));
    expect(res.status).toBe(400);
    expect(res.body.length).toBeGreaterThan(0);
  });

  it('GET /query?pre=UNKNOWN returns 404', async () => {
    const res = await httpGet(`${baseUrl}/query?pre=UNKNOWN`);
    expect(res.status).toBe(404);
  });

  it('GET /nonexistent returns 405', async () => {
    const res = await httpGet(`${baseUrl}/nonexistent`);
    expect(res.status).toBe(405);
  });

  it('server listens and closes cleanly', async () => {
    // The server is already listening (beforeAll). Verify address is valid.
    const addr = server.address();
    expect(addr).not.toBeNull();
    expect(typeof addr).toBe('object');
  });
});
