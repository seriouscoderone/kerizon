/**
 * Run the conformance harness against the kerizon CLI.
 * This is the interop verification — same tests that run against kli,
 * now running against our implementation.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KerizonAdapter } from '../src/adapter/kerizon-adapter.js';
import { checkSequenceMonotonicity } from '../src/invariants/sequence.js';
import { checkAllFirstSeenInvariants } from '../src/invariants/first-seen.js';
import { checkPreRotationChain } from '../src/invariants/pre-rotation.js';
import { checkStreamSelfFraming, checkVersionString, checkAttachmentOrder, findCountCodes } from '../src/invariants/cesr-stream.js';
import { resolve } from 'node:path';

const CLI_PATH = resolve(import.meta.dirname, '../../kerizon-cli/dist/cli.js');
let adapter: KerizonAdapter;
const KS = `kerizon-conform-${Date.now()}`;

beforeAll(async () => {
  adapter = new KerizonAdapter({
    cliPath: CLI_PATH,
    useNode: true,
    keystoreName: KS,
  });
  await adapter.init({ name: KS, nopasscode: true });
});

describe('kerizon conformance — lifecycle', () => {
  it('init creates a keystore', async () => {
    // Already done in beforeAll, verify via a second init attempt or status
    const ks2 = `kerizon-conform2-${Date.now()}`;
    const a2 = new KerizonAdapter({ cliPath: CLI_PATH, useNode: true, keystoreName: ks2 });
    const r = await a2.init({ name: ks2, nopasscode: true });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Keystore created');
  });

  it('incept creates an identifier with valid prefix', async () => {
    const r = await adapter.incept({
      alias: 'conform-alice',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });
    expect(r.exitCode).toBe(0);
    expect(r.prefix).toBeTruthy();
    expect(r.prefix!.length).toBe(44);
    expect(r.prefix!.startsWith('E')).toBe(true); // Blake3-256 SAID prefix
  });

  it('status returns correct key state', async () => {
    const r = await adapter.status('conform-alice');
    expect(r.exitCode).toBe(0);
    expect(r.keyState).toBeTruthy();
    expect(r.keyState!.sn).toBe(0);
    expect(r.keyState!.currentKeys.length).toBe(1);
    expect(r.keyState!.currentKeys[0].startsWith('D')).toBe(true); // Ed25519 key
  });

  it('rotate increments sn and changes keys', async () => {
    const before = await adapter.status('conform-alice');
    const r = await adapter.rotate({ alias: 'conform-alice' });
    expect(r.exitCode).toBe(0);

    const after = await adapter.status('conform-alice');
    expect(after.keyState!.sn).toBe(1);
    expect(after.keyState!.currentKeys).not.toEqual(before.keyState!.currentKeys);
  });

  it('interact increments sn without changing keys', async () => {
    const before = await adapter.status('conform-alice');
    const r = await adapter.interact({ alias: 'conform-alice' });
    expect(r.exitCode).toBe(0);

    const after = await adapter.status('conform-alice');
    expect(after.keyState!.sn).toBe(before.keyState!.sn + 1);
    expect(after.keyState!.currentKeys).toEqual(before.keyState!.currentKeys);
  });

  it('sign produces valid signatures', async () => {
    const r = await adapter.sign('conform-alice', 'hello world');
    expect(r.exitCode).toBe(0);
    expect(r.signatures).toBeTruthy();
    expect(r.signatures!.length).toBeGreaterThan(0);
    expect(r.signatures![0].length).toBe(88); // Ed25519 indexed sig
  });

  it('verify accepts valid signature', async () => {
    const signed = await adapter.sign('conform-alice', 'test message');
    const status = await adapter.status('conform-alice');
    const r = await adapter.verify(status.keyState!.prefix, 'test message', signed.signatures!);
    expect(r.exitCode).toBe(0);
    expect(r.valid).toBe(true);
  });

  it('list shows the identifier', async () => {
    const r = await adapter.list();
    expect(r.exitCode).toBe(0);
    expect(r.identifiers).toBeTruthy();
    expect(r.identifiers!.some(id => id.name === 'conform-alice')).toBe(true);
  });
});

describe('kerizon conformance — event invariants', () => {
  it('exported events have monotonic sequence numbers', async () => {
    const r = await adapter.exportEvents('conform-alice');
    expect(r.exitCode).toBe(0);
    expect(r.events).toBeTruthy();
    expect(r.events!.length).toBe(3); // icp + rot + ixn

    const parsed = r.events!.map(e => ({ sn: e.sn }));
    expect(checkSequenceMonotonicity(parsed).valid).toBe(true);
  });

  it('exported events satisfy first-seen invariants', async () => {
    const r = await adapter.exportEvents('conform-alice');
    const events = r.events!.map(e => JSON.parse(e.raw));
    expect(checkAllFirstSeenInvariants(events).valid).toBe(true);
  });

  it('inception event has i == d (prefix equals SAID)', async () => {
    const r = await adapter.exportEvents('conform-alice');
    const icp = JSON.parse(r.events![0].raw);
    expect(icp['i']).toBe(icp['d']);
    expect(icp['t']).toBe('icp');
  });

  it('prefix is constant across all events', async () => {
    const r = await adapter.exportEvents('conform-alice');
    const prefix = r.events![0].prefix;
    expect(r.events!.every(e => e.prefix === prefix)).toBe(true);
  });

  it('hash chain: every non-inception event.p == prior event.d', async () => {
    const r = await adapter.exportEvents('conform-alice');
    const events = r.events!.map(e => JSON.parse(e.raw));
    for (let i = 1; i < events.length; i++) {
      expect(events[i]['p']).toBe(events[i - 1]['d']);
    }
  });
});

describe('kerizon conformance — CESR stream', () => {
  it('export produces CESR bytes', async () => {
    const r = await adapter.exportKel('conform-alice');
    expect(r.exitCode).toBe(0);
    expect(r.cesr).toBeTruthy();
    expect(r.cesr!.length).toBeGreaterThan(0);
  });

  it('exported stream has KERI version strings', async () => {
    const r = await adapter.exportKel('conform-alice');
    const check = checkVersionString(r.cesr!);
    expect(check.valid).toBe(true);
  });

  it('attachments follow event bodies', async () => {
    const r = await adapter.exportKel('conform-alice');
    const check = checkAttachmentOrder(r.cesr!);
    expect(check.valid).toBe(true);
  });

  it('count codes present in export', async () => {
    const r = await adapter.exportKel('conform-alice');
    const check = findCountCodes(r.cesr!);
    expect(check.codes.length).toBeGreaterThan(0);
    expect(check.valid).toBe(true);
  });
});

describe('kerizon conformance — negative tests', () => {
  it('non-transferable identifier rejects rotation', async () => {
    const r = await adapter.incept({
      alias: 'conform-nt',
      transferable: false,
      signingKeyCount: 1,
      nextKeyCount: 0,
    });
    expect(r.exitCode).toBe(0);

    const rot = await adapter.rotate({ alias: 'conform-nt' });
    expect(rot.exitCode).not.toBe(0);
  });

  it('establishment-only identifier rejects interaction', async () => {
    const r = await adapter.incept({
      alias: 'conform-eo',
      transferable: true,
      establishmentOnly: true,
    });
    expect(r.exitCode).toBe(0);

    const ixn = await adapter.interact({ alias: 'conform-eo' });
    expect(ixn.exitCode).not.toBe(0);
  });

  it('verify rejects invalid signature', async () => {
    const status = await adapter.status('conform-alice');
    const fakeSig = 'AA' + 'A'.repeat(86); // valid-looking but wrong sig
    const r = await adapter.verify(status.keyState!.prefix, 'test', [fakeSig]);
    expect(r.valid).toBe(false);
  });
});
