import type { IMailboxStore } from "../interfaces/IMailboxStore.js";
import type { IKeyStateResolver } from "../interfaces/IKeyStateResolver.js";
import type { ProvisionResult } from "../types/results.js";
import type { AID } from "../types/AID.js";
import { toAID } from "../types/AID.js";
import { parseSad } from "../core/SadParser.js";
import { parseAttachments } from "../core/AttachmentParser.js";
import { evaluateThreshold } from "../core/ThresholdEvaluator.js";

export interface MailboxProvisionerOptions {
  store: IMailboxStore;
  resolver: IKeyStateResolver;
  /** The AID of this mailbox service instance. */
  mailboxAid: AID;
}

/**
 * Handles KERI /end/role/add and /end/role/cut authorization replies.
 *
 * A controller provisions this mailbox by sending a signed /end/role/add reply
 * with `a.role = "mailbox"` and `a.eid = <this mailboxAid>`.
 * The provisioner verifies the reply signature and delegates to IMailboxStore.
 */
export class MailboxProvisioner {
  private readonly store: IMailboxStore;
  private readonly resolver: IKeyStateResolver;
  private readonly mailboxAid: AID;

  constructor(opts: MailboxProvisionerOptions) {
    this.store = opts.store;
    this.resolver = opts.resolver;
    this.mailboxAid = opts.mailboxAid;
  }

  /**
   * Process a CESR-encoded /end/role/add or /end/role/cut reply.
   *
   * Steps:
   *   1. Parse the SAD to extract route and attributes.
   *   2. Verify the reply is addressed to this mailbox.
   *   3. Verify the controller's signatures satisfy their threshold.
   *   4. Provision or deprovision accordingly.
   */
  async processAuthorization(reply: Uint8Array): Promise<ProvisionResult> {
    let parsed;
    try {
      parsed = parseSad(reply);
    } catch (e) {
      return { ok: false, reason: `Failed to parse reply: ${e}` };
    }

    const { fields, raw, attachments } = parsed;

    const route = fields.r as string | undefined;
    if (route !== "/end/role/add" && route !== "/end/role/cut") {
      return {
        ok: false,
        reason: `Expected route '/end/role/add' or '/end/role/cut', got '${route}'`,
      };
    }

    const attrs = fields.a as
      | { cid?: string; role?: string; eid?: string }
      | undefined;
    if (!attrs?.cid || !attrs.role || !attrs.eid) {
      return {
        ok: false,
        reason: "Missing required attributes: cid, role, or eid",
      };
    }

    if (attrs.role !== "mailbox") {
      return {
        ok: false,
        reason: `Expected role 'mailbox', got '${attrs.role}'`,
      };
    }

    if (attrs.eid !== this.mailboxAid) {
      return {
        ok: false,
        reason: `Reply addresses mailbox '${attrs.eid}', not '${this.mailboxAid}'`,
      };
    }

    const cid = toAID(attrs.cid);

    // Resolve key state, trying refresh if needed
    let keyState = await this.resolver.resolve(cid);
    if (!keyState) {
      keyState = await this.resolver.refresh(cid);
    }
    if (!keyState) {
      return {
        ok: false,
        reason: `Cannot resolve key state for controller ${cid}`,
      };
    }

    const sigs = parseAttachments(attachments);
    const valid = await evaluateThreshold({
      indexedSigs: sigs.indexedSigs,
      coupledSigs: sigs.coupledSigs,
      message: raw,
      keyState,
    });

    if (!valid) {
      return { ok: false, reason: "Signature verification failed" };
    }

    if (route === "/end/role/add") {
      await this.store.provision(cid);
    } else {
      await this.store.deprovision(cid);
    }

    return { ok: true, aid: cid };
  }

  /** Return true if an AID has provisioned this mailbox. */
  async isAuthorized(recipient: AID): Promise<boolean> {
    return this.store.isProvisioned(recipient);
  }

  /** Return all AIDs that have provisioned this mailbox. */
  async listAuthorized(): Promise<AID[]> {
    return this.store.listProvisioned();
  }
}
