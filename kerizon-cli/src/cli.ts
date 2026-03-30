#!/usr/bin/env node
/**
 * kerizon CLI — a KERI key management tool backed by @kerizon/cesr and @kerizon/keri-core.
 *
 * Output format matches kli (keripy) so the kli-conformance harness can test it.
 */

import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  Signer,
  Siger,
  Verfer,
  Serder,
  Saider,
  MtrDex,
  CtrDex,
  encodeB64,
  b64Index,
  parseStream,
} from '@kerizon/cesr';
import {
  incept,
  rotate,
  interact,
  Kever,
  TraitDex,
  computeNextDigest,
  createRegistry,
  createUpdate,
} from '@kerizon/keri-core';
import { MemoryStore } from './store/memory-store.js';

// ── Arg parsing ───────────────────────────────────────────────────

/**
 * Multi-word commands supported by kerizon CLI.
 * Longer commands are checked first so "vc registry incept" matches before "vc".
 */
const MULTI_WORD_COMMANDS = [
  'vc registry incept',
  'vc create',
  'vc list',
  'oobi resolve',
  'oobi generate',
  'witness start',
  'witness demo',
];

function parseArgs(argv: string[]): { command: string; flags: Record<string, string[]> } {
  const args = argv.slice(2);
  const flags: Record<string, string[]> = {};

  // Try multi-word commands first (longest match wins)
  let command = '';
  let flagStart = 1;

  for (const mc of MULTI_WORD_COMMANDS) {
    const words = mc.split(' ');
    const matches = words.every((w, idx) => args[idx] === w);
    if (matches && words.length > flagStart - 1) {
      command = mc;
      flagStart = words.length;
    }
  }

  if (!command) {
    command = args[0] ?? '';
    flagStart = 1;
  }

  let i = flagStart;
  while (i < args.length) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        if (!flags[key]) flags[key] = [];
        flags[key].push(args[i + 1]);
        i += 2;
      } else {
        // boolean flag
        flags[key] = ['true'];
        i += 1;
      }
    } else {
      i += 1;
    }
  }

  return { command, flags };
}

function getFlag(flags: Record<string, string[]>, key: string): string | undefined {
  return flags[key]?.[0];
}

function getFlagAll(flags: Record<string, string[]>, key: string): string[] {
  return flags[key] ?? [];
}

function hasFlag(flags: Record<string, string[]>, key: string): boolean {
  return key in flags;
}

function getIntFlag(flags: Record<string, string[]>, key: string, defaultVal: number): number {
  const val = getFlag(flags, key);
  return val !== undefined ? parseInt(val, 10) : defaultVal;
}

// ── Store path ────────────────────────────────────────────────────

function storePath(name: string): string {
  return join(homedir(), '.kerizon', name, 'store.json');
}

function storeDir(name: string): string {
  return join(homedir(), '.kerizon', name);
}

function loadStore(name: string): MemoryStore {
  return MemoryStore.load(storePath(name));
}

function saveStore(name: string, store: MemoryStore): void {
  store.save(storePath(name));
}

// ── Witness HTTP helpers ─────────────────────────────────────────

function postToWitness(url: string, cesr: Buffer): Promise<number> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: '/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/cesr',
        'Content-Length': cesr.length,
      },
    }, (res) => {
      // Consume the response body to avoid memory leaks
      res.resume();
      resolve(res.statusCode ?? 500);
    });
    req.on('error', reject);
    req.write(cesr);
    req.end();
  });
}

function buildCesrPayload(serder: Serder, sigQb64s: string[]): Buffer {
  const eventRaw = Buffer.from(serder.raw);
  const countB64 = b64Index(Math.floor(sigQb64s.length / 64)) + b64Index(sigQb64s.length % 64);
  const attachment = `${CtrDex.ControllerIdxSigs}${countB64}${sigQb64s.join('')}`;
  return Buffer.concat([eventRaw, Buffer.from(attachment)]);
}

async function submitToWitnesses(
  store: MemoryStore,
  witnesses: string[],
  serder: Serder,
  sigQb64s: string[],
): Promise<void> {
  if (witnesses.length === 0) return;

  process.stderr.write('Waiting for witness receipts...\n');

  const cesr = buildCesrPayload(serder, sigQb64s);

  const results = await Promise.all(
    witnesses.map(async (witAid) => {
      const baseUrl = store.getEndpoint(witAid);
      if (!baseUrl) {
        process.stderr.write(`Warning: no endpoint for witness ${witAid}, skipping\n`);
        return { witAid, status: -1 };
      }
      const status = await postToWitness(baseUrl, cesr);
      return { witAid, status };
    }),
  );

  for (const r of results) {
    if (r.status === 204) {
      process.stderr.write(`Witness ${r.witAid}: receipt received\n`);
    } else if (r.status === -1) {
      // already warned above
    } else {
      process.stderr.write(`Witness ${r.witAid}: unexpected status ${r.status}\n`);
    }
  }
}

// ── Commands ──────────────────────────────────────────────────────

async function cmdInit(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  if (!name) {
    process.stderr.write('Error: --name is required\n');
    process.exit(1);
  }

  const dir = storeDir(name);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  // Create an empty store
  const store = new MemoryStore();
  saveStore(name, store);

  const path = storePath(name);
  process.stdout.write(`KERI Keystore created at: ${path}\n`);
}

async function cmdIncept(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);

  const transferable = hasFlag(flags, 'transferable');
  const icount = getIntFlag(flags, 'icount', 1);
  let ncount = getIntFlag(flags, 'ncount', transferable ? 1 : 0);
  const isith = getFlag(flags, 'isith') ?? '1';
  let nsith = getFlag(flags, 'nsith') ?? '1';

  if (!transferable) {
    ncount = 0;  // no next keys for non-transferable
    nsith = '0';
  }
  const estOnly = hasFlag(flags, 'est-only');
  const delpre = getFlag(flags, 'delpre');
  const wits = getFlagAll(flags, 'wits');
  const toad = getIntFlag(flags, 'toad', 0);

  // Generate current signing keypairs
  const currentSigners: Signer[] = [];
  for (let i = 0; i < icount; i++) {
    currentSigners.push(await Signer.generate());
  }

  const currentKeys = currentSigners.map(s => s.verfer.qb64);

  // Generate next signing keypairs and compute digests
  const nextSigners: Signer[] = [];
  const nextDigests: string[] = [];
  for (let i = 0; i < ncount; i++) {
    const s = await Signer.generate();
    nextSigners.push(s);
    nextDigests.push(computeNextDigest(s.verfer.qb64));
  }

  // Build config traits
  const configTraits: string[] = [];
  if (estOnly) configTraits.push(TraitDex.EstOnly);

  // Create inception event
  const serder = incept({
    keys: currentKeys,
    nextDigests,
    signingThreshold: isith,
    nextThreshold: nsith,
    witnesses: wits,
    witnessThreshold: toad,
    configTraits,
    delegator: delpre,
  });

  // Sign the event
  const sigers: Siger[] = [];
  for (let i = 0; i < currentSigners.length; i++) {
    const sigBytes = await currentSigners[i].sign(serder.raw);
    sigers.push(Siger.create({ raw: sigBytes, index: i }));
  }

  const sigQb64s = sigers.map(s => s.qb64);

  // Store everything
  const prefix = serder.said;
  store.appendEvent(prefix, serder, sigQb64s);
  store.setAlias(alias, prefix);
  store.setSigners(
    prefix,
    alias,
    currentSigners.map(s => s.qb64),
    nextSigners.map(s => s.qb64),
  );
  const kever = Kever.fromInception(serder);
  store.putKever(prefix, kever);
  saveStore(name, store);

  // Submit to witnesses if --receipt-endpoint
  if (hasFlag(flags, 'receipt-endpoint') && wits.length > 0) {
    await submitToWitnesses(store, wits, serder, sigQb64s);
  }

  // Output (matches kli format)
  process.stdout.write(`Prefix  ${prefix}\n`);
  for (let i = 0; i < currentKeys.length; i++) {
    process.stdout.write(`\tPublic key ${i + 1}:  ${currentKeys[i]}\n`);
  }
}

async function cmdRotate(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  if (!kever.transferable) {
    throw new Error('non-transferable identifier cannot be rotated');
  }

  const identity = store.getIdentity(prefix);
  if (!identity) {
    process.stderr.write(`Error: no identity data for prefix "${prefix}"\n`);
    process.exit(1);
  }

  // The "next" keys from the previous event become the current keys
  const currentSigners: Signer[] = identity.nextSignerQb64s.map(
    qb64 => new Signer({ qb64 }),
  );
  const currentKeys = currentSigners.map(s => s.verfer.qb64);

  // Generate new next keys
  const ncount = getIntFlag(flags, 'next-count', currentSigners.length);
  const nsith = getFlag(flags, 'nsith') ?? kever.nextThreshold;
  const nextSigners: Signer[] = [];
  const nextDigests: string[] = [];
  for (let i = 0; i < ncount; i++) {
    const s = await Signer.generate();
    nextSigners.push(s);
    nextDigests.push(computeNextDigest(s.verfer.qb64));
  }

  const newSn = kever.sn + 1;

  const serder = rotate({
    prefix,
    priorDigest: kever.lastEstSaid,
    sn: newSn,
    keys: currentKeys,
    nextDigests,
    signingThreshold: kever.signingThreshold,
    nextThreshold: nsith,
    witnessThreshold: kever.witnessThreshold,
  });

  // Sign the event
  const sigers: Siger[] = [];
  for (let i = 0; i < currentSigners.length; i++) {
    const sigBytes = await currentSigners[i].sign(serder.raw);
    sigers.push(Siger.create({ raw: sigBytes, index: i }));
  }

  const sigQb64s = sigers.map(s => s.qb64);

  // Update store
  store.appendEvent(prefix, serder, sigQb64s);
  store.setSigners(
    prefix,
    alias,
    currentSigners.map(s => s.qb64),
    nextSigners.map(s => s.qb64),
  );
  const newKever = kever.applyEstablishment(serder);
  store.putKever(prefix, newKever);
  saveStore(name, store);

  // Submit to witnesses if --receipt-endpoint
  if (hasFlag(flags, 'receipt-endpoint') && kever.witnesses.length > 0) {
    await submitToWitnesses(store, kever.witnesses, serder, sigQb64s);
  }

  // Output
  process.stdout.write(`Prefix  ${prefix}\n`);
  process.stdout.write(`New Sequence No.  ${newSn}\n`);
  for (let i = 0; i < currentKeys.length; i++) {
    process.stdout.write(`\tPublic key ${i + 1}:  ${currentKeys[i]}\n`);
  }
}

async function cmdInteract(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const identity = store.getIdentity(prefix);
  if (!identity) {
    process.stderr.write(`Error: no identity data for prefix "${prefix}"\n`);
    process.exit(1);
  }

  // Parse data if provided
  let data: Record<string, unknown>[] | undefined;
  const dataStr = getFlag(flags, 'data');
  if (dataStr) {
    try {
      data = JSON.parse(dataStr);
    } catch {
      process.stderr.write('Error: --data must be valid JSON\n');
      process.exit(1);
    }
  }

  const newSn = kever.sn + 1;

  // For interaction events, the prior digest is the SAID of the last event
  const events = store.getEvents(prefix);
  const lastEvent = events[events.length - 1];
  const priorDigest = lastEvent.serder.said;

  const serder = interact({
    prefix,
    priorDigest,
    sn: newSn,
    data,
  });

  // Sign with current keys
  const currentSigners = identity.currentSignerQb64s.map(
    qb64 => new Signer({ qb64 }),
  );

  const sigers: Siger[] = [];
  for (let i = 0; i < currentSigners.length; i++) {
    const sigBytes = await currentSigners[i].sign(serder.raw);
    sigers.push(Siger.create({ raw: sigBytes, index: i }));
  }

  const sigQb64s = sigers.map(s => s.qb64);

  store.appendEvent(prefix, serder, sigQb64s);
  const newKever = kever.applyInteraction(serder);
  store.putKever(prefix, newKever);
  saveStore(name, store);

  // Submit to witnesses if --receipt-endpoint
  if (hasFlag(flags, 'receipt-endpoint') && kever.witnesses.length > 0) {
    await submitToWitnesses(store, kever.witnesses, serder, sigQb64s);
  }

  // Output
  const currentKeys = currentSigners.map(s => s.verfer.qb64);
  process.stdout.write(`Prefix  ${prefix}\n`);
  process.stdout.write(`New Sequence No.  ${newSn}\n`);
  for (let i = 0; i < currentKeys.length; i++) {
    process.stdout.write(`\tPublic key ${i + 1}:  ${currentKeys[i]}\n`);
  }
}

async function cmdStatus(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const verbose = hasFlag(flags, 'verbose');

  process.stdout.write(`Alias:\t${alias}\n`);
  process.stdout.write(`Identifier: ${prefix}\n`);
  process.stdout.write(`Seq No:\t${kever.sn}\n`);

  if (kever.delegator) {
    process.stdout.write(`    Delegator:  ${kever.delegator}\n`);
  }

  if (kever.witnesses.length > 0) {
    process.stdout.write(`Witnesses:\n`);
    process.stdout.write(`    Count:      ${kever.witnesses.length}\n`);
    process.stdout.write(`    Threshold:  ${kever.witnessThreshold}\n`);
    for (let i = 0; i < kever.witnesses.length; i++) {
      process.stdout.write(`    ${i + 1}. ${kever.witnesses[i]}\n`);
    }
  }

  process.stdout.write(`Public Keys:\n`);
  for (let i = 0; i < kever.currentKeys.length; i++) {
    process.stdout.write(`\t${i + 1}. ${kever.currentKeys[i]}\n`);
  }

  if (verbose) {
    // Print each event as pretty-printed JSON
    const events = store.getEvents(prefix);
    process.stdout.write(`\n`);
    for (const e of events) {
      process.stdout.write(JSON.stringify(e.serder.ked, null, 2) + '\n');
    }
  }
}

async function cmdSign(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  const text = getFlag(flags, 'text');
  if (!name || !alias || text === undefined) {
    process.stderr.write('Error: --name, --alias, and --text are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const identity = store.getIdentity(prefix);
  if (!identity) {
    process.stderr.write(`Error: no identity data for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const ser = new TextEncoder().encode(text);
  const currentSigners = identity.currentSignerQb64s.map(
    qb64 => new Signer({ qb64 }),
  );

  for (let i = 0; i < currentSigners.length; i++) {
    const sigBytes = await currentSigners[i].sign(ser);
    const siger = Siger.create({ raw: sigBytes, index: i });
    process.stdout.write(`${i + 1}. ${siger.qb64}\n`);
  }
}

async function cmdVerify(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const prefix = getFlag(flags, 'prefix');
  const text = getFlag(flags, 'text');
  const sigQb64s = getFlagAll(flags, 'signature');
  if (!name || !prefix || text === undefined || sigQb64s.length === 0) {
    process.stderr.write('Error: --name, --prefix, --text, and --signature are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const ser = new TextEncoder().encode(text);
  let allValid = true;

  for (let i = 0; i < sigQb64s.length; i++) {
    const siger = Siger.fromQb64(sigQb64s[i]);
    const keyIndex = siger.index;

    if (keyIndex >= kever.currentKeys.length) {
      process.stderr.write(`Signature ${i + 1} references key index ${keyIndex} but only ${kever.currentKeys.length} keys exist.\n`);
      allValid = false;
      continue;
    }

    const verfer = new Verfer({ qb64: kever.currentKeys[keyIndex] });
    const valid = await verfer.verify(siger.raw, ser);

    if (valid) {
      process.stdout.write(`Signature ${i + 1} is valid.\n`);
    } else {
      process.stderr.write(`Signature ${i + 1} is invalid.\n`);
      allValid = false;
    }
  }

  if (!allValid) {
    process.exit(1);
  }
}

async function cmdList(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  if (!name) {
    process.stderr.write('Error: --name is required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const aliases = store.listAliases();

  for (const { name: aliasName, prefix } of aliases) {
    process.stdout.write(`${aliasName} (${prefix})\n`);
  }
}

async function cmdExport(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const events = store.getEvents(prefix);

  // Output each event's raw JSON bytes + signature attachment group
  for (const { serder, sigs } of events) {
    // Write raw event bytes
    process.stdout.write(new TextDecoder().decode(serder.raw));

    // Write signature attachment: -A<count_b64><sig1><sig2>...
    const countB64 = b64Index(Math.floor(sigs.length / 64)) + b64Index(sigs.length % 64);
    process.stdout.write(`${CtrDex.ControllerIdxSigs}${countB64}`);
    for (const sig of sigs) {
      process.stdout.write(sig);
    }
  }
}

async function cmdEvent(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const events = store.getEvents(prefix);
  if (events.length === 0) {
    process.stderr.write(`Error: no events for alias "${alias}"\n`);
    process.exit(1);
  }

  // Get the last event
  const lastEvent = events[events.length - 1];
  const serder = lastEvent.serder;

  if (hasFlag(flags, 'said')) {
    process.stdout.write(`${serder.said}\n`);
  } else if (hasFlag(flags, 'sn')) {
    process.stdout.write(`${serder.sn}\n`);
  } else if (hasFlag(flags, 'json')) {
    process.stdout.write(JSON.stringify(serder.ked) + '\n');
  } else if (hasFlag(flags, 'raw')) {
    process.stdout.write(new TextDecoder().decode(serder.raw) + '\n');
  } else {
    // Default: JSON pretty print
    process.stdout.write(JSON.stringify(serder.ked, null, 2) + '\n');
  }
}

async function cmdImport(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const file = getFlag(flags, 'file');
  if (!name) {
    process.stderr.write('Error: --name is required\n');
    process.exit(1);
  }
  if (!file) {
    process.stderr.write('Error: --file is required\n');
    process.exit(1);
  }

  if (!existsSync(file)) {
    process.stderr.write(`Error: file not found: ${file}\n`);
    process.exit(1);
  }

  const store = loadStore(name);
  const data = readFileSync(file);
  const messages = parseStream(new Uint8Array(data));

  if (messages.length === 0) {
    process.stderr.write('Error: no messages found in CESR stream\n');
    process.exit(1);
  }

  let importedCount = 0;

  for (const msg of messages) {
    const serder = msg.serder;
    const prefix = serder.pre;
    const ilk = serder.ilk;
    const sigQb64s = msg.sigers.map(s => s.qb64);

    if (ilk === 'icp' || ilk === 'dip') {
      // Inception event -- create a new Kever
      if (serder.sn !== 0) {
        throw new Error(`Inception event must have sn=0, got sn=${serder.sn}`);
      }
      const kever = Kever.fromInception(serder);
      store.appendEvent(prefix, serder, sigQb64s);
      store.putKever(prefix, kever);
    } else if (ilk === 'rot' || ilk === 'drt') {
      // Establishment event -- apply to existing Kever
      const kever = store.getKever(prefix);
      if (!kever) {
        throw new Error(`No key state for prefix ${prefix} — cannot apply ${ilk} without prior inception`);
      }
      const newKever = kever.applyEstablishment(serder);
      store.appendEvent(prefix, serder, sigQb64s);
      store.putKever(prefix, newKever);
    } else if (ilk === 'ixn') {
      // Interaction event -- apply to existing Kever
      const kever = store.getKever(prefix);
      if (!kever) {
        throw new Error(`No key state for prefix ${prefix} — cannot apply ixn without prior inception`);
      }
      const newKever = kever.applyInteraction(serder);
      store.appendEvent(prefix, serder, sigQb64s);
      store.putKever(prefix, newKever);
    } else {
      // Unknown event type -- store it but don't update key state
      store.appendEvent(prefix, serder, sigQb64s);
    }

    importedCount++;
  }

  saveStore(name, store);

  process.stdout.write(`Imported ${importedCount} events from ${file}\n`);
}

async function cmdVcRegistryIncept(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  const registryName = getFlag(flags, 'registry-name');
  if (!name || !alias || !registryName) {
    process.stderr.write('Error: --name, --alias, and --registry-name are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const identity = store.getIdentity(prefix);
  if (!identity) {
    process.stderr.write(`Error: no identity data for prefix "${prefix}"\n`);
    process.exit(1);
  }

  // Create the registry inception event
  const regSerder = createRegistry({ issuerAid: prefix });
  const regSaid = regSerder.said;

  // Store the registry
  store.putRegistry(registryName, {
    said: regSaid,
    name: registryName,
    events: [regSaid],
  });

  // Create an interaction event anchoring the registry seal
  const newSn = kever.sn + 1;
  const events = store.getEvents(prefix);
  const lastEvent = events[events.length - 1];
  const priorDigest = lastEvent.serder.said;

  const ixnSerder = interact({
    prefix,
    priorDigest,
    sn: newSn,
    data: [{ i: regSaid, s: '0', d: regSaid }],
  });

  // Sign with current keys
  const currentSigners = identity.currentSignerQb64s.map(
    qb64 => new Signer({ qb64 }),
  );

  const sigers: Siger[] = [];
  for (let i = 0; i < currentSigners.length; i++) {
    const sigBytes = await currentSigners[i].sign(ixnSerder.raw);
    sigers.push(Siger.create({ raw: sigBytes, index: i }));
  }

  const sigQb64s = sigers.map(s => s.qb64);

  store.appendEvent(prefix, ixnSerder, sigQb64s);
  const newKever = kever.applyInteraction(ixnSerder);
  store.putKever(prefix, newKever);
  saveStore(name, store);

  process.stdout.write(`Registry SAID: ${regSaid}\n`);
}

async function cmdVcCreate(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  const registryName = getFlag(flags, 'registry-name');
  const schema = getFlag(flags, 'schema');
  const dataFlag = getFlag(flags, 'data');
  if (!name || !alias || !registryName || !schema || !dataFlag) {
    process.stderr.write('Error: --name, --alias, --registry-name, --schema, and --data are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const identity = store.getIdentity(prefix);
  if (!identity) {
    process.stderr.write(`Error: no identity data for prefix "${prefix}"\n`);
    process.exit(1);
  }

  const registry = store.getRegistry(registryName);
  if (!registry) {
    process.stderr.write(`Error: registry "${registryName}" not found\n`);
    process.exit(1);
  }

  // Read data from file (strip leading @) or parse as JSON
  let data: Record<string, unknown>;
  if (dataFlag.startsWith('@')) {
    const filePath = dataFlag.slice(1);
    if (!existsSync(filePath)) {
      process.stderr.write(`Error: data file not found: ${filePath}\n`);
      process.exit(1);
    }
    data = JSON.parse(readFileSync(filePath, 'utf-8'));
  } else {
    data = JSON.parse(dataFlag);
  }

  // Build ACDC and SAIDify
  const acdcTemplate: Record<string, unknown> = {
    v: 'ACDC10JSON000000_',
    d: '',
    i: prefix,
    s: schema,
    a: data,
  };
  const acdc = Saider.saidify(acdcTemplate);
  const credSaid = acdc['d'] as string;

  // Compute the ACDC raw size for the version string
  const acdcRaw = JSON.stringify(acdc);
  const acdcSize = new TextEncoder().encode(acdcRaw).length;
  const sizeHex = acdcSize.toString(16).padStart(6, '0');
  acdc['v'] = `ACDC10JSON${sizeHex}_`;
  // Re-saidify after version string update
  const finalAcdc = Saider.saidify(acdc);
  const finalCredSaid = finalAcdc['d'] as string;
  const finalAcdcRaw = JSON.stringify(finalAcdc);

  // Create TEL update event for issuance
  const lastTelEventSaid = registry.events[registry.events.length - 1];
  const telSn = registry.events.length;
  const telSerder = createUpdate({
    registrySaid: registry.said,
    credentialSaid: finalCredSaid,
    priorSaid: lastTelEventSaid,
    sn: telSn,
    targetState: 'Issued',
  });

  // Update registry events
  registry.events.push(telSerder.said);
  store.putRegistry(registryName, registry);

  // Store the credential
  store.putCredential(finalCredSaid, {
    said: finalCredSaid,
    registrySaid: registry.said,
    state: 'Issued',
    raw: finalAcdcRaw,
  });

  // Create an interaction event anchoring the TEL update seal
  const newSn = kever.sn + 1;
  const events = store.getEvents(prefix);
  const lastEvent = events[events.length - 1];
  const priorDigest = lastEvent.serder.said;

  const ixnSerder = interact({
    prefix,
    priorDigest,
    sn: newSn,
    data: [{ i: registry.said, s: telSn.toString(16), d: telSerder.said }],
  });

  // Sign with current keys
  const currentSigners = identity.currentSignerQb64s.map(
    qb64 => new Signer({ qb64 }),
  );

  const sigers: Siger[] = [];
  for (let i = 0; i < currentSigners.length; i++) {
    const sigBytes = await currentSigners[i].sign(ixnSerder.raw);
    sigers.push(Siger.create({ raw: sigBytes, index: i }));
  }

  const sigQb64s = sigers.map(s => s.qb64);

  store.appendEvent(prefix, ixnSerder, sigQb64s);
  const newKever = kever.applyInteraction(ixnSerder);
  store.putKever(prefix, newKever);
  saveStore(name, store);

  process.stdout.write(`Credential SAID: ${finalCredSaid}\n`);
}

async function cmdVcList(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const credentials = store.listCredentials();
  // Filter to credentials issued by this alias (issuer prefix matches)
  const mine = credentials.filter(c => {
    try {
      const parsed = JSON.parse(c.raw);
      return parsed['i'] === prefix;
    } catch {
      return false;
    }
  });

  for (const cred of mine) {
    process.stdout.write(`${cred.said} ${cred.state}\n`);
  }
}

async function cmdOobiResolve(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const oobi = getFlag(flags, 'oobi');
  const oobiAlias = getFlag(flags, 'oobi-alias');
  if (!name || !oobi) {
    process.stderr.write('Error: --name and --oobi are required\n');
    process.exit(1);
  }

  const store = loadStore(name);

  // Fetch the OOBI URL (GET request)
  const oobiUrl = new URL(oobi);
  const response = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
    http.get(oobi, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 500,
          body: Buffer.concat(chunks).toString('utf-8'),
        });
      });
      res.on('error', reject);
    }).on('error', reject);
  });

  if (response.statusCode !== 200) {
    process.stderr.write(`Error: OOBI fetch returned status ${response.statusCode}\n`);
    process.exit(1);
  }

  // Parse the response body as a KERI event (JSON)
  let ked: Record<string, unknown>;
  try {
    ked = JSON.parse(response.body);
  } catch {
    process.stderr.write('Error: OOBI response is not valid JSON\n');
    process.exit(1);
  }

  const witPrefix = (ked['i'] as string) ?? '';
  if (!witPrefix) {
    process.stderr.write('Error: OOBI event has no prefix (i field)\n');
    process.exit(1);
  }

  // Store the witness inception event so we know the AID
  const witSerder = Serder.fromKed(ked);
  const witKever = Kever.fromInception(witSerder);
  store.appendEvent(witPrefix, witSerder, []);
  store.putKever(witPrefix, witKever);

  // Store the endpoint mapping: AID → base URL (scheme + host + port)
  const baseUrl = `${oobiUrl.protocol}//${oobiUrl.host}`;
  store.putEndpoint(witPrefix, baseUrl);

  // Store alias mapping if provided
  if (oobiAlias) {
    store.setAlias(oobiAlias, witPrefix);
  }

  saveStore(name, store);

  process.stdout.write(`Resolved: ${witPrefix}\n`);
  process.stdout.write(`Endpoint: ${baseUrl}\n`);
  if (oobiAlias) {
    process.stdout.write(`Alias: ${oobiAlias}\n`);
  }
}

async function cmdOobiGenerate(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name');
  const alias = getFlag(flags, 'alias');
  const role = getFlag(flags, 'role') ?? 'witness';
  if (!name || !alias) {
    process.stderr.write('Error: --name and --alias are required\n');
    process.exit(1);
  }

  const store = loadStore(name);
  const prefix = store.getPrefix(alias);
  if (!prefix) {
    process.stderr.write(`Error: alias "${alias}" not found\n`);
    process.exit(1);
  }

  const kever = store.getKever(prefix);
  if (!kever) {
    process.stderr.write(`Error: no key state for prefix "${prefix}"\n`);
    process.exit(1);
  }

  if (role === 'witness') {
    // For each witness, look up its stored URL and output the OOBI URL
    for (const witAid of kever.witnesses) {
      const baseUrl = store.getEndpoint(witAid);
      if (baseUrl) {
        process.stdout.write(`${baseUrl}/oobi/${prefix}/witness\n`);
      } else {
        process.stderr.write(`Warning: no endpoint for witness ${witAid}\n`);
      }
    }
  } else {
    process.stderr.write(`Error: unsupported role "${role}"\n`);
    process.exit(1);
  }
}

async function cmdWitnessStart(flags: Record<string, string[]>): Promise<void> {
  const name = getFlag(flags, 'name') ?? 'witness';
  const httpPort = getIntFlag(flags, 'http', 5642);
  const tcpPort = getIntFlag(flags, 'tcp', 5632);
  const dbPath = join(homedir(), '.kerizon-witness', name);

  mkdirSync(dbPath, { recursive: true });

  const { NedbStore, KerizonWitness, createWitnessHttpServer, createWitnessTcpServer } = await import('@kerizon/witness');
  const store = new NedbStore(dbPath);
  const witness = await KerizonWitness.create({ name, httpPort, tcpPort, dbPath }, store);

  const httpServer = createWitnessHttpServer(witness);
  const tcpServer = createWitnessTcpServer(witness);

  httpServer.listen(httpPort, () => {
    process.stdout.write(`Witness ${name} (${witness.prefix}) HTTP on port ${httpPort}\n`);
  });
  tcpServer.listen(tcpPort, () => {
    process.stdout.write(`Witness ${name} (${witness.prefix}) TCP on port ${tcpPort}\n`);
  });

  // Keep running until SIGTERM
  await new Promise<void>((resolve) => {
    process.on('SIGTERM', () => { httpServer.close(); tcpServer.close(); resolve(); });
    process.on('SIGINT', () => { httpServer.close(); tcpServer.close(); resolve(); });
  });
}

async function cmdWitnessDemo(flags: Record<string, string[]>): Promise<void> {
  const witnesses = [
    { name: 'wan', httpPort: 5642, tcpPort: 5632 },
    { name: 'wil', httpPort: 5643, tcpPort: 5633 },
    { name: 'wes', httpPort: 5644, tcpPort: 5634 },
  ];

  const { NedbStore, KerizonWitness, createWitnessHttpServer, createWitnessTcpServer } = await import('@kerizon/witness');

  for (const w of witnesses) {
    const dbPath = join(homedir(), '.kerizon-witness', w.name);
    mkdirSync(dbPath, { recursive: true });
    const store = new NedbStore(dbPath);
    const witness = await KerizonWitness.create({ ...w, dbPath }, store);

    const http = createWitnessHttpServer(witness);
    const tcp = createWitnessTcpServer(witness);

    http.listen(w.httpPort);
    tcp.listen(w.tcpPort);
    process.stdout.write(`Witness ${w.name} (${witness.prefix}) on HTTP:${w.httpPort} TCP:${w.tcpPort}\n`);
  }

  await new Promise<void>((resolve) => {
    process.on('SIGTERM', resolve);
    process.on('SIGINT', resolve);
  });
}

function cmdVersion(): void {
  process.stdout.write('Library version: 0.1.0\n');
}

// ── Main ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv);

  try {
    switch (command) {
      case 'init':
        await cmdInit(flags);
        break;
      case 'incept':
        await cmdIncept(flags);
        break;
      case 'rotate':
        await cmdRotate(flags);
        break;
      case 'interact':
        await cmdInteract(flags);
        break;
      case 'status':
        await cmdStatus(flags);
        break;
      case 'sign':
        await cmdSign(flags);
        break;
      case 'verify':
        await cmdVerify(flags);
        break;
      case 'list':
        await cmdList(flags);
        break;
      case 'export':
        await cmdExport(flags);
        break;
      case 'import':
        await cmdImport(flags);
        break;
      case 'event':
        await cmdEvent(flags);
        break;
      case 'vc registry incept':
        await cmdVcRegistryIncept(flags);
        break;
      case 'vc create':
        await cmdVcCreate(flags);
        break;
      case 'vc list':
        await cmdVcList(flags);
        break;
      case 'oobi resolve':
        await cmdOobiResolve(flags);
        break;
      case 'oobi generate':
        await cmdOobiGenerate(flags);
        break;
      case 'witness start':
        await cmdWitnessStart(flags);
        break;
      case 'witness demo':
        await cmdWitnessDemo(flags);
        break;
      case 'version':
        cmdVersion();
        break;
      default:
        process.stderr.write(`Unknown command: ${command}\n`);
        process.stderr.write('Usage: kerizon <command> [options]\n');
        process.stderr.write('Commands: init, incept, rotate, interact, status, sign, verify, list, export, import, event, vc registry incept, vc create, vc list, oobi resolve, oobi generate, witness start, witness demo, version\n');
        process.exit(1);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${message}\n`);
    process.exit(1);
  }
}

main();
