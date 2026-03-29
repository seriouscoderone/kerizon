/**
 * Validation Pipeline Utilities:
 *
 * Craft malformed CESR events for testing import rejection.
 * These utilities produce events with specific defects so the harness
 * can verify that a KERI implementation correctly rejects them.
 *
 * The malformed events are serialized in CESR format: JSON body with
 * a minimal attachment group (empty controller indexed sigs counter).
 */

import { computeSaid } from '../util/said.js';

/** Options for crafting a malformed inception event. */
export interface MalformedInceptionOpts {
  /** Use a non-zero sequence number (should be rejected). */
  wrongSn?: number;
  /** Skip SAID computation, insert a bad digest. */
  badSaid?: boolean;
  /** Use wrong field order (non-canonical). */
  wrongFieldOrder?: boolean;
  /** Custom prefix to use instead of SAID-derived. */
  customPrefix?: string;
  /** Custom version string. */
  version?: string;
}

/**
 * Craft an inception event with specific defects.
 *
 * A valid inception event has:
 * - sn = 0 (hex "0")
 * - d == i (both are the SAID)
 * - Fields in order: v, t, d, i, s, kt, k, nt, n, bt, b, c, a
 *
 * This function introduces the requested defects.
 */
export function craftMalformedInception(opts: MalformedInceptionOpts = {}): Record<string, unknown> {
  const version = opts.version ?? 'KERI10JSON000000_';
  const sn = opts.wrongSn != null ? opts.wrongSn.toString(16) : '0';

  // A structurally plausible key (Ed25519 verfer, 44 chars starting with 'D')
  const dummyKey = 'DAbcdefghijklmnopqrstuvwxyz0123456789-_AAAA';
  const dummyDigest = 'EAbcdefghijklmnopqrstuvwxyz0123456789-_AAAA';

  if (opts.wrongFieldOrder) {
    // Intentionally wrong order: put 's' before 'd'
    const event: Record<string, unknown> = {
      v: version,
      t: 'icp',
      s: sn,
      d: '',
      i: '',
      kt: '1',
      k: [dummyKey],
      nt: '1',
      n: [dummyDigest],
      bt: '0',
      b: [],
      c: [],
      a: [],
    };
    // Compute SAID on the wrong-ordered event
    const said = computeSaid(event, 'd', 'E');
    event['d'] = said;
    event['i'] = opts.customPrefix ?? said;
    return event;
  }

  // Standard field order
  const event: Record<string, unknown> = {
    v: version,
    t: 'icp',
    d: '',
    i: '',
    s: sn,
    kt: '1',
    k: [dummyKey],
    nt: '1',
    n: [dummyDigest],
    bt: '0',
    b: [],
    c: [],
    a: [],
  };

  if (opts.badSaid) {
    // Insert a plausible but incorrect SAID
    const wrongSaid = 'E' + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    event['d'] = wrongSaid;
    event['i'] = opts.customPrefix ?? wrongSaid;
  } else {
    const said = computeSaid(event, 'd', 'E');
    event['d'] = said;
    event['i'] = opts.customPrefix ?? said;
  }

  return event;
}

/**
 * Serialize an event dictionary to CESR format.
 *
 * Produces: JSON body + minimal attachment group.
 * The attachment is an empty controller indexed signatures counter (-AAA)
 * which signals zero signatures. This makes the event structurally parseable
 * but cryptographically invalid (no actual signatures).
 *
 * The version string's size field is updated to reflect the actual JSON body size.
 */
export function serializeEvent(event: Record<string, unknown>): Uint8Array {
  // First pass: serialize to get the size
  const jsonStr = JSON.stringify(event);

  // Update the version string with the correct hex size
  const updatedEvent = { ...event };
  const bodySize = new TextEncoder().encode(jsonStr).length;
  const hexSize = bodySize.toString(16).padStart(6, '0');
  const currentVersion = event['v'] as string;
  if (currentVersion && /^KERI\d{2}JSON[0-9a-f]{6}_$/.test(currentVersion)) {
    updatedEvent['v'] = currentVersion.replace(/[0-9a-f]{6}_$/, hexSize + '_');
  }

  // Re-serialize with correct size (size may change if version string changes digit count)
  let finalJson = JSON.stringify(updatedEvent);
  let finalSize = new TextEncoder().encode(finalJson).length;

  // Iterate until the size in the version string matches the actual size
  for (let attempt = 0; attempt < 3; attempt++) {
    const newHexSize = finalSize.toString(16).padStart(6, '0');
    const ver = updatedEvent['v'] as string;
    updatedEvent['v'] = ver.replace(/[0-9a-f]{6}_$/, newHexSize + '_');
    finalJson = JSON.stringify(updatedEvent);
    const newSize = new TextEncoder().encode(finalJson).length;
    if (newSize === finalSize) break;
    finalSize = newSize;
  }

  // Pad JSON body to 4-char boundary (CESR quadlet alignment)
  const jsonBytes = new TextEncoder().encode(finalJson);
  const padding = (4 - (jsonBytes.length % 4)) % 4;
  const paddedJson = new Uint8Array(jsonBytes.length + padding);
  paddedJson.set(jsonBytes);
  // Pad with spaces
  for (let i = jsonBytes.length; i < paddedJson.length; i++) {
    paddedJson[i] = 0x20; // space
  }

  // Minimal attachment: empty controller indexed sigs counter
  // -A is the counter code for controller indexed sigs, AA = count 0
  const attachment = new TextEncoder().encode('-AAA');

  // Combine body + attachment
  const result = new Uint8Array(paddedJson.length + attachment.length);
  result.set(paddedJson);
  result.set(attachment, paddedJson.length);

  return result;
}

/**
 * Craft a rotation event for a prefix that doesn't exist in the target keystore.
 * This should be rejected because the prefix has no prior inception.
 */
export function craftOrphanRotation(prefix: string): Record<string, unknown> {
  const dummyKey = 'DAbcdefghijklmnopqrstuvwxyz0123456789-_AAAA';
  const dummyDigest = 'EAbcdefghijklmnopqrstuvwxyz0123456789-_AAAA';
  const dummyPrior = 'EBbcdefghijklmnopqrstuvwxyz0123456789-_AAAA';

  const event: Record<string, unknown> = {
    v: 'KERI10JSON000000_',
    t: 'rot',
    d: '',
    i: prefix,
    s: '1',
    p: dummyPrior,
    kt: '1',
    k: [dummyKey],
    nt: '1',
    n: [dummyDigest],
    bt: '0',
    br: [],
    ba: [],
    c: [],
    a: [],
  };

  const said = computeSaid(event, 'd', 'E');
  event['d'] = said;
  return event;
}
