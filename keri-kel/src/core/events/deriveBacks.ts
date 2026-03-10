import { WitnessError } from "../../types/errors.js";

/**
 * Derive the new witness list after a rotation event.
 *
 * Algorithm (spec Section 4.7):
 * 1. Verify no duplicates in br (removes)
 * 2. Verify no duplicates in ba (adds)
 * 3. Verify all entries in br exist in current witnesses
 * 4. Verify br ∩ ba = ∅ (cannot remove and add same witness)
 * 5. Verify ba ∩ current_witnesses = ∅ (cannot add existing witness)
 * 6. new_witnesses = [w for w in current if w not in br] + ba
 * 7. Verify no duplicates in result
 * 8. Return new_witnesses
 */
export function deriveBacks(
  currentWitnesses: string[],
  br: string[],
  ba: string[],
): string[] {
  // 1. No duplicates in br
  if (new Set(br).size !== br.length) {
    throw new WitnessError("Duplicate entries in witness removes (br)");
  }

  // 2. No duplicates in ba
  if (new Set(ba).size !== ba.length) {
    throw new WitnessError("Duplicate entries in witness adds (ba)");
  }

  // 3. All br entries must exist in current witnesses
  const currentSet = new Set(currentWitnesses);
  for (const w of br) {
    if (!currentSet.has(w)) {
      throw new WitnessError(
        `Witness remove "${w}" not found in current witness list`,
      );
    }
  }

  // 4. br ∩ ba = ∅
  const brSet = new Set(br);
  for (const w of ba) {
    if (brSet.has(w)) {
      throw new WitnessError(
        `Witness "${w}" appears in both removes (br) and adds (ba)`,
      );
    }
  }

  // 5. ba ∩ current_witnesses = ∅
  for (const w of ba) {
    if (currentSet.has(w)) {
      throw new WitnessError(
        `Witness add "${w}" already exists in current witness list`,
      );
    }
  }

  // 6. Derive new list
  const newWitnesses = currentWitnesses.filter((w) => !brSet.has(w)).concat(ba);

  // 7. No duplicates in result
  if (new Set(newWitnesses).size !== newWitnesses.length) {
    throw new WitnessError("Derived witness list contains duplicates");
  }

  return newWitnesses;
}
