/**
 * T001–T015: Type and Constant Tests
 */
import { describe, it, expect } from "vitest";
import {
  makeKeySet,
  makeKeySituation,
  makeDerivationParameters,
  KeyAlgorithm,
  SecurityTier,
  SecurityTierParams,
} from "../../src/types.js";
import {
  MtrDex,
  makeEncryptedSecretFromRaw,
  encryptedSecretFromQb64,
} from "../../src/cesr-helpers.js";
import { DEFAULT_VAULT_CONFIG } from "../../src/config.js";
import { DerivationError } from "../../src/errors.js";

describe("T001-T006: KeySet / KeySituation / DerivationParameters / PublicKeySet", () => {
  it("T001: KeySet default construction has empty pubs, ridx=0, kidx=0, dt=''", () => {
    const ks = makeKeySet();
    expect(ks.pubs).toEqual([]);
    expect(ks.ridx).toBe(0);
    expect(ks.kidx).toBe(0);
    expect(ks.dt).toBe("");
  });

  it("T002: KeySet construction with explicit values round-trips all fields", () => {
    const ks = makeKeySet({ pubs: ["Dkey1", "Dkey2"], ridx: 3, kidx: 6, dt: "2026-01-01" });
    expect(ks.pubs).toEqual(["Dkey1", "Dkey2"]);
    expect(ks.ridx).toBe(3);
    expect(ks.kidx).toBe(6);
    expect(ks.dt).toBe("2026-01-01");
  });

  it("T003: KeySituation default construction has three default KeySets", () => {
    const ks = makeKeySituation();
    expect(ks.previous).toEqual(makeKeySet());
    expect(ks.current).toEqual(makeKeySet());
    expect(ks.next).toEqual(makeKeySet());
  });

  it("T004: DerivationParameters default has pidx=0, algo=DETERMINISTIC", () => {
    const dp = makeDerivationParameters();
    expect(dp.pidx).toBe(0);
    expect(dp.algorithm).toBe(KeyAlgorithm.DETERMINISTIC);
  });

  it("T005: DerivationParameters preserves encrypted salt field", () => {
    const dp = makeDerivationParameters({ salt: "1AAHsomeencryptedvalue", pidx: 2 });
    expect(dp.salt).toBe("1AAHsomeencryptedvalue");
    expect(dp.pidx).toBe(2);
  });

  it("T006: PublicKeySet stores and retrieves pubs list", () => {
    const pks = { pubs: ["Dabc", "Ddef"] };
    expect(pks.pubs).toEqual(["Dabc", "Ddef"]);
  });
});

describe("T007-T010: KeyAlgorithm / SecurityTier Enumerations", () => {
  it("T007: KeyAlgorithm enumeration values match wire strings", () => {
    expect(KeyAlgorithm.RANDOM).toBe("randy");
    expect(KeyAlgorithm.DETERMINISTIC).toBe("salty");
    expect(KeyAlgorithm.GROUP).toBe("group");
    expect(KeyAlgorithm.EXTERNAL).toBe("extern");
  });

  it("T008: SecurityTier.LOW has ops=2, mem=64MiB", () => {
    const params = SecurityTierParams[SecurityTier.LOW];
    expect(params.ops).toBe(2);
    expect(params.mem).toBe(65536); // 64 MiB in KiB
  });

  it("T009: SecurityTier.MEDIUM has ops=3, mem=256MiB", () => {
    const params = SecurityTierParams[SecurityTier.MEDIUM];
    expect(params.ops).toBe(3);
    expect(params.mem).toBe(262144);
  });

  it("T010: SecurityTier.HIGH has ops=4, mem=1GiB", () => {
    const params = SecurityTierParams[SecurityTier.HIGH];
    expect(params.ops).toBe(4);
    expect(params.mem).toBe(1048576);
  });
});

describe("T011-T014: EncryptedSecret", () => {
  it("T011: EncryptedSecret with X25519_Cipher_Salt has correct raw size (72 bytes)", () => {
    const raw = new Uint8Array(72);
    const es = makeEncryptedSecretFromRaw(raw, MtrDex.X25519_Cipher_Salt);
    expect(es.raw.length).toBe(72);
    expect(es.code).toBe(MtrDex.X25519_Cipher_Salt);
  });

  it("T012: EncryptedSecret with X25519_Cipher_Seed has correct raw size (92 bytes)", () => {
    const raw = new Uint8Array(92);
    const es = makeEncryptedSecretFromRaw(raw, MtrDex.X25519_Cipher_Seed);
    expect(es.raw.length).toBe(92);
    expect(es.code).toBe(MtrDex.X25519_Cipher_Seed);
  });

  it("T013: EncryptedSecret rejects unsupported cipher code", () => {
    const raw = new Uint8Array(32);
    expect(() => makeEncryptedSecretFromRaw(raw, "Z")).toThrow(DerivationError);
  });

  it("T014: EncryptedSecret round-trips through qb64 serialization", () => {
    const raw = new Uint8Array(92).fill(0xab);
    const es = makeEncryptedSecretFromRaw(raw, MtrDex.X25519_Cipher_Seed);
    const decoded = encryptedSecretFromQb64(es.qb64);
    expect(decoded.code).toBe(MtrDex.X25519_Cipher_Seed);
    expect(decoded.raw).toEqual(raw);
  });
});

describe("T015: VaultConfig defaults", () => {
  it("T015: VaultConfig default values match specification", () => {
    expect(DEFAULT_VAULT_CONFIG.defaultAlgorithm).toBe(KeyAlgorithm.DETERMINISTIC);
    expect(DEFAULT_VAULT_CONFIG.defaultSecurityTier).toBe(SecurityTier.LOW);
    expect(DEFAULT_VAULT_CONFIG.eraseOnRotation).toBe(true);
    expect(DEFAULT_VAULT_CONFIG.testMode).toBe(false);
  });
});
