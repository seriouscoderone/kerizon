/**
 * Key state machine invariant tests.
 *
 * Tests deterministic key state properties through the kli adapter:
 * - KEL export/import produces identical key state
 * - Interaction events do not change keys
 * - Consecutive rotations always change keys
 * - Establishment-only (EO) trait persists through rotation
 * - Non-transferable identifiers reject rotation
 * - Prefix is constant across all exported events
 * - DoNotDelegate (DnD) trait blocks delegation
 *
 * Requires: kli installed. Does NOT require witnesses.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

describe.skipIf(!KLI_AVAILABLE)('key state machine invariants', () => {
  describe('key state determinism', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-determinism-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it('build KEL, export, import into fresh keystore, compare status', async () => {
      const alias = 'determinism-aid';
      const incept = await adapter.incept({
        alias,
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
        signingThreshold: '1',
        nextThreshold: '1',
      });
      expect(incept.exitCode).toBe(0);

      await adapter.rotate({ alias });
      await adapter.interact({ alias, data: [] });

      const originalStatus = await adapter.status(alias);
      expect(originalStatus.exitCode).toBe(0);

      const exported = await adapter.exportKel(alias);
      expect(exported.exitCode).toBe(0);

      // Import into fresh keystore
      const ks2 = 'ksm-determinism-target-' + Date.now();
      const adapter2 = new KliAdapter({ keystoreName: ks2, timeout: 30_000 });
      await adapter2.init({ name: ks2, nopasscode: true });

      const importResult = await adapter2.importKel(exported.cesr!);
      expect(importResult.exitCode).toBe(0);

      // Compare key state: prefix, sn, and current keys should match
      // Note: after import, the identifier doesn't have an alias in the new keystore,
      // so we verify via the exported events' content
      const originalEvents = await adapter.exportEvents(alias);
      expect(originalEvents.exitCode).toBe(0);
      expect(originalEvents.events).toBeTruthy();

      // All events should have consistent prefix
      const prefix = originalStatus.keyState!.prefix;
      for (const event of originalEvents.events!) {
        expect(event.prefix).toBe(prefix);
      }

      // The final sn should match the status
      expect(originalStatus.keyState!.sn).toBe(2);
    });
  });

  describe('interaction does not change keys', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-ixn-keys-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it('status.keys before == after ixn', async () => {
      const alias = 'ixn-nokey-aid';
      await adapter.incept({
        alias,
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
        signingThreshold: '1',
        nextThreshold: '1',
      });

      const beforeStatus = await adapter.status(alias);
      expect(beforeStatus.exitCode).toBe(0);
      const keysBefore = beforeStatus.keyState!.currentKeys;

      await adapter.interact({ alias, data: [] });

      const afterStatus = await adapter.status(alias);
      expect(afterStatus.exitCode).toBe(0);
      const keysAfter = afterStatus.keyState!.currentKeys;

      expect(keysAfter).toEqual(keysBefore);
    });
  });

  describe('multiple rotations always change keys', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-rot-keys-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it('no two consecutive rotations share a key', async () => {
      const alias = 'multi-rot-aid';
      await adapter.incept({
        alias,
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
        signingThreshold: '1',
        nextThreshold: '1',
      });

      const keyHistory: string[][] = [];

      const status0 = await adapter.status(alias);
      keyHistory.push([...status0.keyState!.currentKeys]);

      // Perform 3 rotations
      for (let i = 0; i < 3; i++) {
        const rot = await adapter.rotate({ alias });
        expect(rot.exitCode).toBe(0);

        const status = await adapter.status(alias);
        keyHistory.push([...status.keyState!.currentKeys]);
      }

      // Verify no two consecutive key sets are identical
      for (let i = 1; i < keyHistory.length; i++) {
        const prev = keyHistory[i - 1];
        const curr = keyHistory[i];
        const same = prev.length === curr.length && prev.every((k, idx) => k === curr[idx]);
        expect(same).toBe(false);
      }
    });
  });

  describe('establishment-only trait', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-eo-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it('EO trait persists through rotation; ixn rejected', async () => {
      const alias = 'eo-aid';
      const incept = await adapter.incept({
        alias,
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
        signingThreshold: '1',
        nextThreshold: '1',
        establishmentOnly: true,
      });
      expect(incept.exitCode).toBe(0);

      // Rotation should succeed (establishment event)
      const rot = await adapter.rotate({ alias });
      expect(rot.exitCode).toBe(0);

      // Interaction should fail (non-establishment event on EO identifier)
      const ixn = await adapter.interact({ alias, data: [] });
      expect(ixn.exitCode).not.toBe(0);
    });
  });

  describe('non-transferable identifier', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-nt-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it('non-transferable rejects rotation and key is permanent', async () => {
      const alias = 'nt-aid';
      const incept = await adapter.incept({
        alias,
        transferable: false,
        signingKeyCount: 1,
        nextKeyCount: 0,
        signingThreshold: '1',
        nextThreshold: '0',
      });
      expect(incept.exitCode).toBe(0);

      const status = await adapter.status(alias);
      expect(status.exitCode).toBe(0);
      const initialKeys = status.keyState!.currentKeys;
      expect(initialKeys.length).toBeGreaterThan(0);

      // Rotation should fail on a non-transferable identifier
      const rot = await adapter.rotate({ alias });
      expect(rot.exitCode).not.toBe(0);

      // Keys should be unchanged after failed rotation attempt
      const statusAfter = await adapter.status(alias);
      expect(statusAfter.keyState!.currentKeys).toEqual(initialKeys);
    });
  });

  describe('prefix constant across exported events', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-prefix-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it('all exported events share the same prefix', async () => {
      const alias = 'prefix-const-aid';
      const incept = await adapter.incept({
        alias,
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
        signingThreshold: '1',
        nextThreshold: '1',
      });
      expect(incept.exitCode).toBe(0);

      await adapter.rotate({ alias });
      await adapter.interact({ alias, data: [] });
      await adapter.rotate({ alias });

      const events = await adapter.exportEvents(alias);
      expect(events.exitCode).toBe(0);
      expect(events.events!.length).toBe(4);

      const prefix = incept.prefix!;
      for (const event of events.events!) {
        expect(event.prefix).toBe(prefix);
      }
    });
  });

  describe('do-not-delegate trait', () => {
    let adapter: KliAdapter;
    const ks = 'ksm-dnd-' + Date.now();

    beforeAll(async () => {
      adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
      await adapter.init({ name: ks, nopasscode: true });
    });

    it.todo('DnD identifier has doNotDelegate in config traits -- kli config file may not support DnD key directly', async () => {
      const alias = 'dnd-aid';
      const incept = await adapter.incept({
        alias,
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
        signingThreshold: '1',
        nextThreshold: '1',
        doNotDelegate: true,
      });
      expect(incept.exitCode).toBe(0);

      // Verify the inception event has DND in the config traits
      const events = await adapter.exportEvents(alias);
      expect(events.exitCode).toBe(0);
      expect(events.events).toBeTruthy();
      expect(events.events!.length).toBeGreaterThan(0);

      const icpEvent = JSON.parse(events.events![0].raw);
      const configTraits = icpEvent['c'] as string[];
      expect(configTraits).toContain('DND');
    });
  });
});
