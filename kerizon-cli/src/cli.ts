#!/usr/bin/env node
/**
 * kerizon CLI — a KERI key management tool backed by @kerizon/cesr and @kerizon/keri-core.
 *
 * Output format matches kli (keripy) so the kli-conformance harness can test it.
 */

import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  Signer,
  Siger,
  Verfer,
  Serder,
  MtrDex,
  CtrDex,
  encodeB64,
  b64Index,
} from '@kerizon/cesr';
import {
  incept,
  rotate,
  interact,
  Kever,
  TraitDex,
  computeNextDigest,
} from '@kerizon/keri-core';
import { MemoryStore } from './store/memory-store.js';

// ── Arg parsing ───────────────────────────────────────────────────

function parseArgs(argv: string[]): { command: string; flags: Record<string, string[]> } {
  const args = argv.slice(2);
  const command = args[0] ?? '';
  const flags: Record<string, string[]> = {};

  let i = 1;
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
  const ncount = getIntFlag(flags, 'ncount', transferable ? 1 : 0);
  const isith = getFlag(flags, 'isith') ?? '1';
  const nsith = getFlag(flags, 'nsith') ?? '1';
  const estOnly = hasFlag(flags, 'est-only');
  const delpre = getFlag(flags, 'delpre');

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
  const ncount = currentSigners.length;
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
    nextThreshold: kever.nextThreshold,
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
      case 'event':
        await cmdEvent(flags);
        break;
      case 'version':
        cmdVersion();
        break;
      default:
        process.stderr.write(`Unknown command: ${command}\n`);
        process.stderr.write('Usage: kerizon <command> [options]\n');
        process.stderr.write('Commands: init, incept, rotate, interact, status, sign, verify, list, export, event, version\n');
        process.exit(1);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${message}\n`);
    process.exit(1);
  }
}

main();
