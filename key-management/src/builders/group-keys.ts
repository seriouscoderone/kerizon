/**
 * GroupKeySetBuilder — assembles signing and rotating key sets from multiple group members.
 *
 * Cross-ref: habbing.py:2622 (GroupHab), habbing.py:633 (extractMerfersMigers)
 */
import type { Verfer, Diger } from "../cesr-helpers.js";
import { matterDecode, makeDiger, MtrDex } from "../cesr-helpers.js";
import { DerivationError } from "../errors.js";
import { blake3 } from "@noble/hashes/blake3";
import type { KeyStateSnapshot } from "kel-event-processing";

/** A member's key state contribution. */
export interface MemberKeyState {
  prefix: string;
  sequenceNumber: number;
  keys: string[];      // current signing keys (verfer qb64s)
  nextKeys: string[];  // next key digests (diger qb64s)
}

export class GroupKeySetBuilder {
  private _signingMembers: Array<{ prefix: string; sequenceNumber: number }> = [];
  private _rotatingMembers: Array<{ prefix: string; sequenceNumber: number }> = [];
  private _signingThreshold: string | number | string[][] = "1";
  private _nextThreshold: string | number | string[][] = "1";
  private _memberKeyStates: Map<string, MemberKeyState> = new Map();

  addSigningMember(prefix: string, sequenceNumber: number): this {
    this._signingMembers.push({ prefix, sequenceNumber });
    return this;
  }

  addRotatingMember(prefix: string, sequenceNumber: number): this {
    this._rotatingMembers.push({ prefix, sequenceNumber });
    return this;
  }

  signingThreshold(threshold: string | number | string[][]): this {
    this._signingThreshold = threshold;
    return this;
  }

  nextThreshold(threshold: string | number | string[][]): this {
    this._nextThreshold = threshold;
    return this;
  }

  /**
   * Provide the key state for a member (used during build).
   */
  withMemberKeyState(prefix: string, state: MemberKeyState): this {
    this._memberKeyStates.set(prefix, state);
    return this;
  }

  build(): { verfers: Verfer[]; digers: Diger[] } {
    if (this._signingMembers.length === 0) {
      throw new DerivationError("GroupKeySetBuilder: no signing members");
    }

    const verfers: Verfer[] = [];
    const digers: Diger[] = [];

    // Extract verfers from signing members
    for (const member of this._signingMembers) {
      const state = this._memberKeyStates.get(member.prefix);
      if (!state) {
        throw new DerivationError(
          `GroupKeySetBuilder: no key state for signing member: ${member.prefix}`,
        );
      }
      for (const keyQb64 of state.keys) {
        const raw = matterDecode(keyQb64);
        const code = keyQb64[0];
        const transferable = code !== MtrDex.Ed25519N;
        verfers.push({
          raw,
          code,
          qb64: keyQb64,
          qb64b: new TextEncoder().encode(keyQb64),
          transferable,
        });
      }
    }

    // Extract digers from rotating members
    const rotMems = this._rotatingMembers.length > 0
      ? this._rotatingMembers
      : this._signingMembers;

    for (const member of rotMems) {
      const state = this._memberKeyStates.get(member.prefix);
      if (!state) {
        throw new DerivationError(
          `GroupKeySetBuilder: no key state for rotating member: ${member.prefix}`,
        );
      }
      for (const digestQb64 of state.nextKeys) {
        const raw = matterDecode(digestQb64);
        const code = digestQb64[0];
        digers.push({
          raw,
          code,
          qb64: digestQb64,
          qb64b: new TextEncoder().encode(digestQb64),
        });
      }
    }

    // Validate threshold
    const tSize = typeof this._signingThreshold === "string"
      ? parseInt(this._signingThreshold, 10) || 1
      : typeof this._signingThreshold === "number"
        ? this._signingThreshold
        : 1;

    if (tSize > verfers.length) {
      throw new DerivationError(
        `GroupKeySetBuilder: signing threshold (${tSize}) exceeds key count (${verfers.length})`,
      );
    }

    return { verfers, digers };
  }
}
