# Kerizon Witness Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a lightweight kerizon witness service with nedb persistence, native HTTP server, and TCP transport — enabling the 12 skipped conformance tests to pass.

**Architecture:** New `kerizon-witness/` package. Uses `nedb-promises` for persistent storage, Node.js native `http.createServer` for the HTTP API, and `net.createServer` for TCP CESR streams. The witness auto-incepts a non-transferable Ed25519 identity on startup, serves its own OOBI, processes submitted events by verifying and signing receipts, and serves KEL queries. The kerizon CLI gets `witness start` and `witness demo` commands.

**Tech Stack:** TypeScript, nedb-promises, node:http, node:net, @kerizon/cesr, @kerizon/keri-core

---

## File Structure

```
kerizon-witness/
  package.json
  tsconfig.json
  vitest.config.ts
  src/
    store/
      nedb-store.ts         # NeDB-backed KEL + key state + receipt persistence
      types.ts              # Store interface
    server/
      http-server.ts        # Native http.createServer — event submission, OOBI, KEL query
      tcp-server.ts         # Native net.createServer — CESR stream transport
    witness.ts              # Witness core: auto-incept, process event, sign receipt
    config.ts               # WitnessConfig: name, ports, salt
    index.ts                # Public API
  tests/
    store/
      nedb-store.test.ts
    witness.test.ts
    server/
      http-server.test.ts

kerizon-cli/
  src/
    cli.ts                  # MODIFY: add `witness start` and `witness demo` commands
```

---

### Task 1: NeDB persistent store

**Files:**
- Create: `kerizon-witness/package.json`, `tsconfig.json`, `vitest.config.ts`
- Create: `kerizon-witness/src/store/types.ts`
- Create: `kerizon-witness/src/store/nedb-store.ts`
- Test: `kerizon-witness/tests/store/nedb-store.test.ts`

The store persists:
- KEL events (prefix → ordered events with CESR + sigs)
- Key state (prefix → serialized Kever fields)
- Receipts (eventSaid → receipt signatures)
- Witness identity (the witness's own Signer qb64 + Kever)

Interface:
```typescript
export interface WitnessStore {
  putEvent(prefix: string, sn: number, said: string, cesr: Uint8Array, sigs: string[]): Promise<void>;
  getEvents(prefix: string): Promise<Array<{ sn: number; said: string; cesr: Uint8Array; sigs: string[] }>>;
  getEvent(prefix: string, sn: number): Promise<{ said: string; cesr: Uint8Array; sigs: string[] } | null>;
  putKeyState(prefix: string, state: Record<string, unknown>): Promise<void>;
  getKeyState(prefix: string): Promise<Record<string, unknown> | null>;
  putReceipt(eventSaid: string, receipt: { signerAid: string; signature: string }): Promise<void>;
  getReceipts(eventSaid: string): Promise<Array<{ signerAid: string; signature: string }>>;
  putWitnessIdentity(signerQb64: string, prefix: string): Promise<void>;
  getWitnessIdentity(): Promise<{ signerQb64: string; prefix: string } | null>;
}
```

Tests: put/get events, put/get key state, put/get receipts, persistence across instances (same db path).

---

### Task 2: Witness core — auto-incept + receipt signing

**Files:**
- Create: `kerizon-witness/src/witness.ts`
- Create: `kerizon-witness/src/config.ts`
- Test: `kerizon-witness/tests/witness.test.ts`

```typescript
// witness.ts
export class KerizonWitness {
  readonly prefix: string;  // witness AID (non-transferable, B prefix)

  static async create(config: WitnessConfig, store: WitnessStore): Promise<KerizonWitness>;

  /** Process a submitted CESR event: verify, store, sign receipt. */
  async processEvent(cesr: Uint8Array): Promise<{ receipt: string; eventSaid: string } | { error: string }>;

  /** Get the witness's own inception KEL as CESR bytes. */
  getOwnKel(): Uint8Array;

  /** Get a stored AID's KEL as CESR bytes. */
  async getKel(prefix: string): Promise<Uint8Array | null>;
}
```

```typescript
// config.ts
export interface WitnessConfig {
  name: string;
  httpPort: number;
  tcpPort: number;
  salt?: string;     // deterministic key generation
  dbPath?: string;   // nedb file path (default: ~/.kerizon-witness/<name>/)
}
```

The witness:
1. On create: check store for existing identity, or auto-incept a non-transferable Ed25519 AID
2. processEvent: parse CESR → extract Serder + Sigs → verify sigs against key state → store event → sign receipt with witness key → store receipt → return receipt
3. getOwnKel: return the witness's inception event as CESR
4. getKel: return stored events for a prefix as concatenated CESR

Tests: create produces non-transferable AID (B prefix), processEvent accepts valid inception, processEvent returns receipt, getOwnKel returns CESR, persistence across restart.

---

### Task 3: HTTP server — event submission + OOBI + KEL query

**Files:**
- Create: `kerizon-witness/src/server/http-server.ts`
- Test: `kerizon-witness/tests/server/http-server.test.ts`

```typescript
// http-server.ts
import http from 'node:http';

export function createWitnessHttpServer(witness: KerizonWitness): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url!, `http://${req.headers.host}`);

    if (req.method === 'POST' && url.pathname === '/') {
      // Submit CESR event — witness processes and returns receipt
      const body = await readBody(req);
      const result = await witness.processEvent(body);
      if ('error' in result) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end(result.error);
      } else {
        res.writeHead(204);
        res.end();
      }
    }
    else if (req.method === 'GET' && url.pathname.startsWith('/oobi/')) {
      // Serve OOBI: return witness's own KEL as CESR
      const kel = witness.getOwnKel();
      res.writeHead(200, { 'Content-Type': 'application/cesr+json' });
      res.end(Buffer.from(kel));
    }
    else if (req.method === 'GET' && url.pathname === '/query') {
      // KEL query by prefix
      const prefix = url.searchParams.get('pre');
      if (!prefix) { res.writeHead(400); res.end('missing pre'); return; }
      const kel = await witness.getKel(prefix);
      if (!kel) { res.writeHead(404); res.end('not found'); return; }
      res.writeHead(200, { 'Content-Type': 'application/cesr+json' });
      res.end(Buffer.from(kel));
    }
    else {
      res.writeHead(405);
      res.end('Method Not Allowed');
    }
  });
}
```

Tests: start server on random port, POST event → 204, GET /oobi/{aid}/controller → 200 + CESR, GET /query?pre=X → 200 + CESR, POST invalid → 400.

---

### Task 4: TCP server — CESR stream transport

**Files:**
- Create: `kerizon-witness/src/server/tcp-server.ts`
- Test: (minimal — TCP tested via integration)

```typescript
// tcp-server.ts
import net from 'node:net';

export function createWitnessTcpServer(witness: KerizonWitness): net.Server {
  return net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', async (data) => {
      buffer = Buffer.concat([buffer, data]);
      // Try to process complete CESR messages
      const result = await witness.processEvent(new Uint8Array(buffer));
      if ('receipt' in result) {
        socket.write(result.receipt);
        buffer = Buffer.alloc(0);
      }
    });
  });
}
```

---

### Task 5: CLI `witness start` + `witness demo`

**Files:**
- Modify: `kerizon-cli/src/cli.ts`
- Create: `kerizon-cli/src/commands/witness.ts`

```
kerizon witness start --name <name> --http <port> --tcp <port> [--salt <salt>]
kerizon witness demo
```

`witness start`: creates a KerizonWitness + HTTP server + TCP server, runs until SIGTERM.

`witness demo`: starts 3 witnesses (wan, wil, wes) on fixed ports matching keripy's demo:
- wan: HTTP 5642, TCP 5632
- wil: HTTP 5643, TCP 5633
- wes: HTTP 5644, TCP 5634

Uses deterministic salts so AIDs are reproducible.

---

### Task 6: Wire into conformance harness + run skipped tests

**Files:**
- Modify: `kli-conformance/tests/kli-witnesses-available.ts` — detect kerizon witnesses
- Create: `kli-conformance/tests/kerizon-witness-conformance.test.ts`

Tests against our own witness:
1. Start kerizon witness demo
2. kerizon incept with witness → receipt received
3. kerizon OOBI generate → URL contains witness AID
4. kerizon OOBI resolve → success
5. Cross-verify: kerizon signs with witnessed AID → kli verifies

---

## Self-Review

**Spec coverage:**
- witness-service/api: submitEvent ✓, getReceipt ✓, queryKerl ✓, resolveOobi ✓
- accountability/receipting: createReceipt ✓ (witness signs), classifyReceipt ✓ (non-transferable)
- discovery: OOBI served ✓, endpoint resolved ✓
- persistence: nedb replaces JSON file for witness ✓

**Deferred:** Mailbox (message relay), gossip dissemination (witness-to-witness), watcher service, cloud agent. These need multi-service coordination beyond a single witness.

**Type consistency:** WitnessStore interface used in both nedb-store and witness.ts. KerizonWitness used in both HTTP and TCP servers.
