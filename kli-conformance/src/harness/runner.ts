/**
 * Conformance suite runner.
 *
 * Orchestrates running the full test suite against a CLI adapter.
 * This module provides programmatic access to run conformance checks
 * outside of vitest, e.g., from a CI script or another test framework.
 */

import type { CliAdapter } from '../adapter/types.js';
import { checkSequenceMonotonicity } from '../invariants/sequence.js';
import { checkKeyCommitmentChain } from '../invariants/key-commitment.js';
import { checkWitnessThresholdChain } from '../invariants/witness-threshold.js';
import { checkPreRotationChain, checkSaidIntegrity } from '../invariants/pre-rotation.js';
import { checkAllFirstSeenInvariants } from '../invariants/first-seen.js';

export interface ConformanceResult {
  readonly tier: string;
  readonly name: string;
  readonly passed: boolean;
  readonly violations: string[];
  readonly durationMs: number;
}

export interface SuiteResult {
  readonly adapter: string;
  readonly results: ConformanceResult[];
  readonly totalPassed: number;
  readonly totalFailed: number;
  readonly durationMs: number;
}

/**
 * Run the full conformance suite against an adapter.
 *
 * This runs T2 event invariant checks by creating an identifier,
 * performing operations, exporting the KEL, and verifying invariants.
 */
export async function runConformanceSuite(
  adapter: CliAdapter,
  opts: {
    alias?: string;
    rotationCount?: number;
    interactionCount?: number;
  } = {},
): Promise<SuiteResult> {
  const alias = opts.alias ?? 'conformance-test';
  const rotCount = opts.rotationCount ?? 3;
  const ixnCount = opts.interactionCount ?? 2;
  const results: ConformanceResult[] = [];
  const suiteStart = performance.now();

  // 1. Incept
  const inceptResult = await adapter.incept({
    alias,
    transferable: true,
    signingKeyCount: 1,
    nextKeyCount: 1,
  });

  if (inceptResult.exitCode !== 0) {
    return {
      adapter: adapter.name,
      results: [{
        tier: 'setup',
        name: 'incept',
        passed: false,
        violations: [`Inception failed: ${inceptResult.stderr}`],
        durationMs: inceptResult.durationMs,
      }],
      totalPassed: 0,
      totalFailed: 1,
      durationMs: performance.now() - suiteStart,
    };
  }

  // 2. Rotations
  for (let i = 0; i < rotCount; i++) {
    await adapter.rotate({ alias });
  }

  // 3. Interactions
  for (let i = 0; i < ixnCount; i++) {
    await adapter.interact({ alias });
  }

  // 4. Export events
  const exported = await adapter.exportEvents(alias);
  if (!exported.events || exported.events.length === 0) {
    results.push({
      tier: 'setup',
      name: 'export',
      passed: false,
      violations: ['No events exported'],
      durationMs: exported.durationMs,
    });
  }

  const events = (exported.events ?? []).map(e => JSON.parse(e.raw));

  // 5. Run invariant checks
  const checks: Array<{ tier: string; name: string; check: () => { valid: boolean; violations?: string[] } }> = [
    {
      tier: 'T2',
      name: 'sequence-monotonicity',
      check: () => {
        const parsed = events.map((e: Record<string, unknown>) => ({
          sn: typeof e['s'] === 'string' ? parseInt(e['s'] as string, 16) : 0,
        }));
        const r = checkSequenceMonotonicity(parsed);
        return { valid: r.valid, violations: r.violation ? [r.violation] : [] };
      },
    },
    {
      tier: 'T2',
      name: 'key-commitment-chain',
      check: () => checkKeyCommitmentChain(events),
    },
    {
      tier: 'T2',
      name: 'witness-threshold-chain',
      check: () => checkWitnessThresholdChain(events),
    },
    {
      tier: 'T2',
      name: 'pre-rotation-chain',
      check: () => checkPreRotationChain(events),
    },
    {
      tier: 'T2',
      name: 'said-integrity',
      check: () => checkSaidIntegrity(events),
    },
    {
      tier: 'T2',
      name: 'first-seen-ordering',
      check: () => checkAllFirstSeenInvariants(events),
    },
  ];

  for (const { tier, name, check } of checks) {
    const start = performance.now();
    const result = check();
    results.push({
      tier,
      name,
      passed: result.valid,
      violations: result.violations ?? [],
      durationMs: performance.now() - start,
    });
  }

  const totalPassed = results.filter(r => r.passed).length;
  const totalFailed = results.filter(r => !r.passed).length;

  return {
    adapter: adapter.name,
    results,
    totalPassed,
    totalFailed,
    durationMs: performance.now() - suiteStart,
  };
}
