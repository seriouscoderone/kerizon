import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { createHttpServer } from '../src/http-adapter.js';
import { KerizonWitness, NedbStore } from '@kerizon/witness';
import type { WitnessHandler } from '@kerizon/witness';
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

describe('HTTP adapter', () => {
  let dbDir: string;
  let store: NedbStore;
  let witness: KerizonWitness;
  let handler: WitnessHandler;
  let server: { listen(port: number): Promise<void>; stop(): Promise<void> };
  let baseUrl: string;
  const testPort = 19642 + Math.floor(Math.random() * 1000);

  beforeAll(async () => {
    dbDir = await mkdtemp(join(tmpdir(), 'witness-http-test-'));
    store = new NedbStore(dbDir);
    witness = await KerizonWitness.create(
      { name: 'wit-http', httpPort: testPort, tcpPort: 0 },
      store,
    );
    handler = witness.createHandler();
    server = createHttpServer(handler);
    await server.listen(testPort);
    baseUrl = `http://127.0.0.1:${testPort}`;
  });

  afterAll(async () => {
    await server.stop();
    await store.close();
    await rm(dbDir, { recursive: true, force: true });
  });

  it('GET /oobi/anything returns 200 with inception + loc/scheme reply', async () => {
    const res = await httpGet(`${baseUrl}/oobi/anything`);
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);

    // Find the first JSON object (inception event)
    let depth = 0;
    let icpEnd = 0;
    for (let i = 0; i < res.body.length; i++) {
      if (res.body[i] === '{') depth++;
      if (res.body[i] === '}') depth--;
      if (depth === 0 && res.body[i] === '}') { icpEnd = i + 1; break; }
    }
    const icpJson = res.body.slice(0, icpEnd);
    const icpParsed = JSON.parse(icpJson);
    expect(icpParsed.v).toBeDefined();
    expect(icpParsed.t).toBe('icp');
    expect(icpParsed.i[0]).toBe('B');

    // After the inception + sig attachment, find the reply message
    // Skip past the -A counter (4 chars) + sig (88 chars) = 92 chars
    const afterIcp = icpEnd + 92;
    depth = 0;
    let rpyEnd = 0;
    for (let i = afterIcp; i < res.body.length; i++) {
      if (res.body[i] === '{') depth++;
      if (res.body[i] === '}') depth--;
      if (depth === 0 && res.body[i] === '}') { rpyEnd = i + 1; break; }
    }
    expect(rpyEnd).toBeGreaterThan(afterIcp);
    const rpyJson = res.body.slice(afterIcp, rpyEnd);
    const rpyParsed = JSON.parse(rpyJson);
    expect(rpyParsed.t).toBe('rpy');
    expect(rpyParsed.r).toBe('/loc/scheme');
    expect(rpyParsed.a.eid).toBe(witness.prefix);
    expect(rpyParsed.a.scheme).toBe('http');
    expect(rpyParsed.a.url).toContain('http://127.0.0.1:');

    // After the reply JSON, there should be a -C counter + couple
    const rpyAttach = res.body.slice(rpyEnd);
    expect(rpyAttach.startsWith('-C')).toBe(true);
    // Couple: counter (4) + prefix (44) + cigar (88) = 136 chars
    expect(rpyAttach.length).toBe(4 + 44 + 88);
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
});
