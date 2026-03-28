/**
 * KEL State Machine Model for model-based testing.
 *
 * Defines a model of expected KERI key state and fast-check commands
 * that drive the CLI through random sequences of operations.
 * After each command, the model state is compared against the CLI's
 * actual state via adapter.status().
 *
 * This is the most powerful testing tool in the harness: fast-check
 * generates thousands of random command sequences and shrinks failures
 * to the minimal reproduction case.
 */

import fc from 'fast-check';
import type { CliAdapter, KeyState } from '../adapter/types.js';

// ─── Model ─────────────────────────────────────────────────────

export interface KelModel {
  initialized: boolean;
  prefix: string;
  sn: number;
  transferable: boolean;
  establishmentOnly: boolean;
  doNotDelegate: boolean;
  abandoned: boolean;
}

export function initialModel(): KelModel {
  return {
    initialized: false,
    prefix: '',
    sn: -1,
    transferable: true,
    establishmentOnly: false,
    doNotDelegate: false,
    abandoned: false,
  };
}

// ─── Commands ──────────────────────────────────────────────────

/**
 * Inception command: create a new identifier.
 * Precondition: no identifier exists yet.
 * Postcondition: prefix is set, sn = 0.
 */
export class InceptCommand implements fc.AsyncCommand<KelModel, CliAdapter> {
  readonly alias: string;
  readonly transferable: boolean;
  readonly establishmentOnly: boolean;

  constructor(alias: string, transferable: boolean, establishmentOnly: boolean) {
    this.alias = alias;
    this.transferable = transferable;
    this.establishmentOnly = establishmentOnly;
  }

  check(model: Readonly<KelModel>): boolean {
    return !model.initialized;
  }

  async run(model: KelModel, adapter: CliAdapter): Promise<void> {
    const result = await adapter.incept({
      alias: this.alias,
      transferable: this.transferable,
      signingKeyCount: 1,
      nextKeyCount: 1,
      signingThreshold: '1',
      nextThreshold: '1',
      establishmentOnly: this.establishmentOnly,
    });

    if (result.exitCode !== 0) {
      throw new Error(`Inception failed: ${result.stderr}`);
    }

    model.initialized = true;
    model.prefix = result.prefix ?? '';
    model.sn = 0;
    model.transferable = this.transferable;
    model.establishmentOnly = this.establishmentOnly;

    // Verify against CLI
    const status = await adapter.status(this.alias);
    assertSnMatches(status.keyState, model);
  }

  toString(): string {
    return `Incept(alias=${this.alias}, transferable=${this.transferable}, EO=${this.establishmentOnly})`;
  }
}

/**
 * Rotation command: rotate keys.
 * Precondition: identifier exists, transferable, not abandoned.
 * Postcondition: sn increments by 1.
 */
export class RotateCommand implements fc.AsyncCommand<KelModel, CliAdapter> {
  readonly alias: string;

  constructor(alias: string) {
    this.alias = alias;
  }

  check(model: Readonly<KelModel>): boolean {
    return model.initialized && model.transferable && !model.abandoned;
  }

  async run(model: KelModel, adapter: CliAdapter): Promise<void> {
    const result = await adapter.rotate({ alias: this.alias });

    if (result.exitCode !== 0) {
      throw new Error(`Rotation failed: ${result.stderr}`);
    }

    model.sn += 1;

    const status = await adapter.status(this.alias);
    assertSnMatches(status.keyState, model);
  }

  toString(): string {
    return `Rotate(alias=${this.alias})`;
  }
}

/**
 * Interaction command: create an interaction event.
 * Precondition: identifier exists, EO trait not set.
 * Postcondition: sn increments by 1, keys unchanged.
 */
export class InteractCommand implements fc.AsyncCommand<KelModel, CliAdapter> {
  readonly alias: string;

  constructor(alias: string) {
    this.alias = alias;
  }

  check(model: Readonly<KelModel>): boolean {
    return model.initialized && !model.establishmentOnly;
  }

  async run(model: KelModel, adapter: CliAdapter): Promise<void> {
    const result = await adapter.interact({ alias: this.alias });

    if (result.exitCode !== 0) {
      throw new Error(`Interaction failed: ${result.stderr}`);
    }

    model.sn += 1;

    const status = await adapter.status(this.alias);
    assertSnMatches(status.keyState, model);
  }

  toString(): string {
    return `Interact(alias=${this.alias})`;
  }
}

/**
 * Negative test: attempt to rotate a non-transferable identifier.
 * Precondition: identifier exists and is non-transferable.
 * Postcondition: rotation fails, sn unchanged.
 */
export class RotateNonTransferableCommand implements fc.AsyncCommand<KelModel, CliAdapter> {
  readonly alias: string;

  constructor(alias: string) {
    this.alias = alias;
  }

  check(model: Readonly<KelModel>): boolean {
    return model.initialized && !model.transferable;
  }

  async run(model: KelModel, adapter: CliAdapter): Promise<void> {
    const result = await adapter.rotate({ alias: this.alias });

    // Rotation of non-transferable MUST fail
    if (result.exitCode === 0) {
      throw new Error('Rotation of non-transferable identifier should have failed');
    }

    // sn should not have changed
    const status = await adapter.status(this.alias);
    assertSnMatches(status.keyState, model);
  }

  toString(): string {
    return `RotateNonTransferable(alias=${this.alias})`;
  }
}

/**
 * Negative test: attempt to interact with an establishment-only identifier.
 * Precondition: identifier exists and has EO trait.
 * Postcondition: interaction fails, sn unchanged.
 */
export class InteractEstOnlyCommand implements fc.AsyncCommand<KelModel, CliAdapter> {
  readonly alias: string;

  constructor(alias: string) {
    this.alias = alias;
  }

  check(model: Readonly<KelModel>): boolean {
    return model.initialized && model.establishmentOnly;
  }

  async run(model: KelModel, adapter: CliAdapter): Promise<void> {
    const result = await adapter.interact({ alias: this.alias });

    // Interaction with EO identifier MUST fail
    if (result.exitCode === 0) {
      throw new Error('Interaction with establishment-only identifier should have failed');
    }

    // sn should not have changed
    const status = await adapter.status(this.alias);
    assertSnMatches(status.keyState, model);
  }

  toString(): string {
    return `InteractEstOnly(alias=${this.alias})`;
  }
}

// ─── Assertions ────────────────────────────────────────────────

function assertSnMatches(keyState: KeyState | undefined, model: KelModel): void {
  if (!keyState) {
    throw new Error('status returned no key state');
  }
  if (keyState.sn !== model.sn) {
    throw new Error(`sn mismatch: CLI reports ${keyState.sn}, model expects ${model.sn}`);
  }
}

// ─── Command generators ────────────────────────────────────────

/**
 * Generate a sequence of commands for a transferable identifier.
 * Inception + random rotations and interactions.
 */
export function arbTransferableCommands(alias: string): fc.Arbitrary<fc.AsyncCommand<KelModel, CliAdapter>[]> {
  const incept = fc.constant(new InceptCommand(alias, true, false));
  const rotate = fc.constant(new RotateCommand(alias));
  const interact = fc.constant(new InteractCommand(alias));

  return fc.tuple(
    incept,
    fc.array(fc.oneof(rotate, interact), { minLength: 1, maxLength: 8 }),
  ).map(([icp, rest]) => [icp, ...rest]);
}

/**
 * Generate a sequence of commands for a non-transferable identifier.
 * Inception + attempted rotation (should fail).
 */
export function arbNonTransferableCommands(alias: string): fc.Arbitrary<fc.AsyncCommand<KelModel, CliAdapter>[]> {
  return fc.constant([
    new InceptCommand(alias, false, false),
    new RotateNonTransferableCommand(alias),
  ]);
}

/**
 * Generate a sequence of commands for an establishment-only identifier.
 * Inception + rotations + attempted interaction (should fail).
 */
export function arbEstOnlyCommands(alias: string): fc.Arbitrary<fc.AsyncCommand<KelModel, CliAdapter>[]> {
  return fc.tuple(
    fc.constant(new InceptCommand(alias, true, true)),
    fc.array(fc.constant(new RotateCommand(alias)), { minLength: 0, maxLength: 3 }),
    fc.constant(new InteractEstOnlyCommand(alias)),
  ).map(([icp, rots, ixn]) => [icp, ...rots, ixn]);
}
