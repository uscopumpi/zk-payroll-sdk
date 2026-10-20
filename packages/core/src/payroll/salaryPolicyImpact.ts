/**
 * Minimal structural view of a payroll period: the recipient amounts that make
 * up the period. Any object with this shape is accepted, so callers do not have
 * to depend on a concrete period class.
 */
export interface SalaryPolicyPeriod {
  /** Recipient amounts included in the period. */
  entries: readonly { recipientId: string; amount: bigint }[];
}

/**
 * A description of a single salary policy change applied to a payroll period.
 */
export interface SalaryPolicyChange {
  /** Stable identifier of the affected employee/account. */
  recipientId: string;
  /** Previous per-period salary amount (in the smallest unit). */
  previousAmount: bigint;
  /** New per-period salary amount (in the smallest unit). */
  newAmount: bigint;
}

/**
 * Options controlling how the impact analysis is computed.
 */
export interface SalaryPolicyImpactOptions {
  /**
   * Total amount available to fund the payroll period. When provided, the
   * analysis reports whether the new policy exceeds the available funding.
   */
  availableFunds?: bigint;
  /**
   * Minimum allowed per-period amount. Changes that would push a recipient
   * below this threshold are flagged as violations.
   */
  minimumAmount?: bigint;
  /**
   * Maximum allowed per-period amount. Changes that would push a recipient
   * above this threshold are flagged as violations.
   */
  maximumAmount?: bigint;
}

/**
 * Per-recipient impact detail.
 */
export interface SalaryPolicyImpactEntry {
  recipientId: string;
  previousAmount: bigint;
  newAmount: bigint;
  /** Signed delta: newAmount - previousAmount. */
  delta: bigint;
  /** True when the new amount is greater than the previous amount. */
  increase: boolean;
  /** True when the new amount is less than the previous amount. */
  decrease: boolean;
  /** True when the amount is unchanged. */
  unchanged: boolean;
}

/**
 * Aggregated impact of a salary policy change over a payroll period.
 */
export interface SalaryPolicyImpactReport {
  /** Per-recipient impact entries, in input order. */
  entries: SalaryPolicyImpactEntry[];
  /** Number of recipients whose amount increased. */
  increasedCount: number;
  /** Number of recipients whose amount decreased. */
  decreasedCount: number;
  /** Number of recipients whose amount was unchanged. */
  unchangedCount: number;
  /** Sum of all positive deltas. */
  totalIncrease: bigint;
  /** Sum of all negative deltas (absolute value). */
  totalDecrease: bigint;
  /** Net delta across all recipients. */
  netDelta: bigint;
  /** Total payroll amount before the change. */
  totalPreviousAmount: bigint;
  /** Total payroll amount after the change. */
  totalNewAmount: bigint;
  /** Whether the new total exceeds the available funds, when provided. */
  exceedsAvailableFunds: boolean;
  /** Entries that violate the configured minimum/maximum bounds. */
  boundViolations: SalaryPolicyBoundViolation[];
  /** True when there are no bound violations. */
  isValid: boolean;
}

/**
 * Describes a single recipient amount that falls outside the configured
 * bounds.
 */
export interface SalaryPolicyBoundViolation {
  recipientId: string;
  amount: bigint;
  kind: "below_minimum" | "above_maximum";
  bound: bigint;
}

/**
 * Error thrown when the impact analysis input is invalid.
 */
export class SalaryPolicyImpactValidationError extends Error {
  constructor(
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "SalaryPolicyImpactValidationError";
  }
}

function assertVialeId(id: unknown, index: number): asserts id is string {
  if (typeof id !== "string" || id.trim().length === 0) {
    throw new SalaryPolicyImpactValidationError(
      `Salary policy change at index ${index} is missing a valid recipientId.`,
      { index }
    );
  }
}

function assertNonNegativeAmount(
  value: unknown,
  label: string,
  index: number
): asserts value is bigint {
  if (typeof value !== "bigint") {
    throw new SalaryPolicyImpactValidationError(
      `Salary policy change at index ${index} has a non-bigint ${label}.`,
      { index, label }
    );
  }
  if (value < 0n) {
    throw new SalaryPolicyImpactValidationError(
      `Ray policy change at index ${index} has a negative ${label}.`,
      { index, label }
    );
  }
}

function assertOptionalAmount(value: unknown, label: string): asserts value is bigint | undefined {
  if (value === undefined) {
    return;
  }
  if (typeof value !== "bigint") {
    throw new SalaryPolicyImpactValidationError(
      `Salary policy impact option "${label}" must be a bigint when provided.`,
      { label }
    );
  }
  if (value < 0n) {
    throw new SalaryPolicyImpactValidationError(
      `Salary policy impact option "${label}" must not be negative.`,
      { label }
    );
  }
}

/**
 * Compute the impact of a salary policy change on a payroll period.
 *
 * The function is pure: it does not mutate inputs and returns a deterministic
 * report. It validates all inputs and throws `@SalaryPolicyImpactValidationError`
 * with actionable details when the input is malformed.
 */
export function analyzeSalaryPolicyImpact(
  changes: readonly SalaryPolicyChange[],
  options: SalaryPolicyImpactOptions = {}
): SalaryPolicyImpactReport {
  if (!Array.isArray(changes)) {
    throw new SalaryPolicyImpactValidationError(
      "Salary policy changes must be provided as an array."
    );
  }

  assertOptionalAmount(options.availableFunds, "availableFunds");
  assertOptionalAmount(options.minimumAmount, "minimumAmount");
  assertOptionalAmount(options.maximumAmount, "maximumAmount");

  if (
    options.minimumAmount !== undefined &&
    options.maximumAmount !== undefined &&
    options.minimumAmount > options.maximumAmount
  ) {
    throw new SalaryPolicyImpactValidationError(
      'Salary policy impact option "minimumAmount" must not exceed "maximumAmount".',
      { minimumAmount: options.minimumAmount, maximumAmount: options.maximumAmount }
    );
  }

  const seen = new Set<string>();
  const entries: SalaryPolicyImpactEntry[] = [];
  const boundViolations: SalaryPolicyBoundViolation[] = [];

  let increasedCount = 0;
  let decreasedCount = 0;
  let unchangedCount = 0;
  let totalIncrease = 0n;
  let totalDecrease = 0n;
  let totalPreviousAmount = 0n;
  let totalNewAmount = 0n;

  changes.forEach((change: SalaryPolicyChange, index: number) => {
    if (change === null || typeof change !== "object") {
      throw new SalaryPolicyImpactValidationError(
        `Salary policy change at index ${index} must be an object.`,
        { index }
      );
    }

    assertVialeId(change.recipientId, index);
    assertNonNegativeAmount(change.previousAmount, "previousAmount", index);
    assertNonNegativeAmount(change.newAmount, "newAmount", index);

    if (seen.has(change.recipientId)) {
      throw new SalaryPolicyImpactValidationError(
        `Duplicate salary policy change for recipient "${change.recipientId}".`,
        { recipientId: change.recipientId, index }
      );
    }
    seen.add(change.recipientId);

    const delta = change.newAmount - change.previousAmount;
    const increase = delta > 0n;
    const decrease = delta < 0n;
    const unchanged = delta === 0n;

    if (increase) {
      increasedCount += 1;
      totalIncrease += delta;
    } else if (decrease) {
      decreasedCount += 1;
      totalDecrease += -delta;
    } else {
      unchangedCount += 1;
    }

    totalPreviousAmount += change.previousAmount;
    totalNewAmount += change.newAmount;

    if (options.minimumAmount !== undefined && change.newAmount < options.minimumAmount) {
      boundViolations.push({
        recipientId: change.recipientId,
        amount: change.newAmount,
        kind: "below_minimum",
        bound: options.minimumAmount,
      });
    }

    if (options.maximumAmount !== undefined && change.newAmount > options.maximumAmount) {
      boundViolations.push({
        recipientId: change.recipientId,
        amount: change.newAmount,
        kind: "above_maximum",
        bound: options.maximumAmount,
      });
    }

    entries.push({
      recipientId: change.recipientId,
      previousAmount: change.previousAmount,
      newAmount: change.newAmount,
      delta,
      increase,
      decrease,
      unchanged,
    });
  });

  const exceedsAvailableFunds =
    options.availableFunds !== undefined && totalNewAmount > options.availableFunds;

  return {
    entries,
    increasedCount,
    decreasedCount,
    unchangedCount,
    totalIncrease,
    totalDecrease,
    netDelta: totalIncrease - totalDecrease,
    totalPreviousAmount,
    totalNewAmount,
    exceedsAvailableFunds,
    boundViolations,
    isValid: boundViolations.length === 0,
  };
}

/**
 * Convenience helper that asserts the impact report is valid and that the new
 * total does not exceed available funds. Throws a `SalaryPolicyImpactValidationError`
 * with actionable details otherwise.
 */
export function assertSalaryPolicyImpactIsApplicable(report: SalaryPolicyImpactReport): void {
  if (!report.isValid) {
    throw new SalaryPolicyImpactValidationError(
      "Salary policy change violates configured amount bounds.",
      { boundViolations: report.boundViolations }
    );
  }
  if (report.exceedsAvailableFunds) {
    throw new SalaryPolicyImpactValidationError("Salary policy change exceeds available funds.", {
      totalNewAmount: report.totalNewAmount,
    });
  }
}

/**
 * Returns the set of recipient ids whose amount changed. Useful for building
 * notifications or audit trails without re-deriving the full report.
 */
export function collectChangedRecipientIds(report: SalaryPolicyImpactReport): string[] {
  return report.entries.filter((e) => !e.unchanged).map((e) => e.recipientId);
}

/**
 * Derives the salary policy changes from two payroll periods. This is the
 * primary integration point for the sdk layer: given a previous period and a
 * proposed period, it produces the change list that analyzeSalaryPolicyImpact
 * consumes. Recipients present in only one of the periods are treated as a
 * change from/to zero.
 */
export function deriveSalaryPolicyChangesFromPeriods(
  previous: SalaryPolicyPeriod,
  proposed: SalaryPolicyPeriod
): SalaryPolicyChange[] {
  if (!previous || typeof previous !== "object") {
    throw new SalaryPolicyImpactValidationError(
      "Previous payroll period is required to derive salary policy changes."
    );
  }
  if (!proposed || typeof proposed !== "object") {
    throw new SalaryPolicyImpactValidationError(
      "Proposed payroll period is required to derive salary policy changes."
    );
  }

  const previousMap = new Map<string, bigint>();
  for (const entry of previous.entries) {
    if (!entry || typeof entry.recipientId !== "string") {
      throw new SalaryPolicyImpactValidationError(
        "Previous payroll period contains an entry without a recipientId."
      );
    }
    if (previousMap.has(entry.recipientId)) {
      throw new SalaryPolicyImpactValidationError(
        `Duplicate recipient "${entry.recipientId}" in previous payroll period.`,
        { recipientId: entry.recipientId }
      );
    }
    previousMap.set(entry.recipientId, entry.amount);
  }

  const proposedMap = new Map<string, bigint>();
  for (const entry of proposed.entries) {
    if (!entry || typeof entry.recipientId !== "string") {
      throw new SalaryPolicyImpactValidationError(
        "Proposed payroll period contains an entry without a recipientId."
      );
    }
    if (proposedMap.has(entry.recipientId)) {
      throw new SalaryPolicyImpactValidationError(
        `Duplicate recipient "${entry.recipientId}" in proposed payroll period.`,
        { recipientId: entry.recipientId }
      );
    }
    proposedMap.set(entry.recipientId, entry.amount);
  }

  const orderedIds: string[] = [];
  const seenIds = new Set<string>();
  for (const entry of proposed.entries) {
    if (!seenIds.has(entry.recipientId)) {
      seenIds.add(entry.recipientId);
      orderedIds.push(entry.recipientId);
    }
  }
  for (const entry of previous.entries) {
    if (!seenIds.has(entry.recipientId)) {
      seenIds.add(entry.recipientId);
      orderedIds.push(entry.recipientId);
    }
  }

  return orderedIds.map((recipientId) => ({
    recipientId,
    previousAmount: previousMap.get(recipientId) ?? 0n,
    newAmount: proposedMap.get(recipientId) ?? 0n,
  }));
}
