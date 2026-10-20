import {
  analyzeSalaryPolicyImpact,
  assertSalaryPolicyImpactIsApplicable,
  collectChangedRecipientIds,
  deriveSalaryPolicyChangesFromPeriods,
  SalaryPolicyImpactValidationError,
} from "../../src/payroll/salaryPolicyImpact";

describe("analyzeSalaryPolicyImpact", () => {
  it("computes increases, decreases, and unchanged amounts", () => {
    const report = analyzeSalaryPolicyImpact([
      { recipientId: "alice", previousAmount: 100n, newAmount: 150n },
      { recipientId: "bob", previousAmount: 200n, newAmount: 150n },
      { recipientId: "carol", previousAmount: 50n, newAmount: 50n },
    ]);

    expect(report.entries).toHaveLength(3);
    expect(report.increasedCount).toBe(1);
    expect(report.decreasedCount).toBe(1);
    expect(report.unchangedCount).toBe(1);
    expect(report.totalIncrease).toBe(50n);
    expect(report.totalDecrease).toBe(50n);
    expect(report.netDelta).toBe(0n);
    expect(report.totalPreviousAmount).toBe(350n);
    expect(report.totalNewAmount).toBe(350n);
    expect(report.isValid).toBe(true);
    expect(report.exceedsAvailableFunds).toBe(false);
  });

  it("reports funding shortfall when the new total exceeds available funds", () => {
    const report = analyzeSalaryPolicyImpact(
      [{ recipientId: "alice", previousAmount: 100n, newAmount: 500n }],
      { availableFunds: 200n }
    );

    expect(report.exceedsAvailableFunds).toBe(true);
    expect(() => assertSalaryPolicyImpactIsApplicable(report)).toThrow(
      SalaryPolicyImpactValidationError
    );
  });

  it("flags bound violations and marks the report invalid", () => {
    const report = analyzeSalaryPolicyImpact(
      [
        { recipientId: "alice", previousAmount: 100n, newAmount: 5n },
        { recipientId: "bob", previousAmount: 100n, newAmount: 10_000n },
      ],
      { minimumAmount: 10n, maximumAmount: 1_000n }
    );

    expect(report.isValid).toBe(false);
    expect(report.boundViolations).toHaveLength(2);
    expect(report.boundViolations[0].kind).toBe("below_minimum");
    expect(report.boundViolations[1].kind).toBe("above_maximum");
    expect(() => assertSalaryPolicyImpactIsApplicable(report)).toThrow(
      SalaryPolicyImpactValidationError
    );
  });

  it("rejects duplicate recipient entries", () => {
    expect(() =>
      analyzeSalaryPolicyImpact([
        { recipientId: "alice", previousAmount: 10n, newAmount: 20n },
        { recipientId: "alice", previousAmount: 20n, newAmount: 30n },
      ])
    ).toThrow(SalaryPolicyImpactValidationError);
  });

  it("rejects negative amounts", () => {
    expect(() =>
      analyzeSalaryPolicyImpact([{ recipientId: "alice", previousAmount: -1n, newAmount: 20n }])
    ).toThrow(SalaryPolicyImpactValidationError);
  });

  it("rejects an inverted min/max bound", () => {
    expect(() =>
      analyzeSalaryPolicyImpact([], { minimumAmount: 100n, maximumAmount: 10n })
    ).toThrow(SalaryPolicyImpactValidationError);
  });

  it("handles an empty change list as a valid no-op", () => {
    const report = analyzeSalaryPolicyImpact([]);
    expect(report.entries).toHaveLength(0);
    expect(report.isValid).toBe(true);
    expect(report.netDelta).toBe(0n);
  });
});

describe("collectChangedRecipientIds", () => {
  it("excludes unchanged recipients", () => {
    const report = analyzeSalaryPolicyImpact([
      { recipientId: "alice", previousAmount: 10n, newAmount: 20n },
      { recipientId: "bob", previousAmount: 10n, newAmount: 10n },
    ]);

    expect(collectChangedRecipientIds(report)).toEqual(["alice"]);
  });
});

describe("deriveSalaryPolicyChangesFromPeriods", () => {
  const makePeriod = (entries: { recipientId: string; amount: bigint }[]) =>
    ({ entries }) as { entries: { recipientId: string; amount: bigint }[] };

  it("produces changes including added and removed recipients", () => {
    const changes = deriveSalaryPolicyChangesFromPeriods(
      makePeriod([
        { recipientId: "alice", amount: 100n },
        { recipientId: "bob", amount: 200n },
      ]),
      makePeriod([
        { recipientId: "alice", amount: 150n },
        { recipientId: "carol", amount: 50n },
      ])
    );

    expect(changes).toEqual([
      { recipientId: "alice", previousAmount: 100n, newAmount: 150n },
      { recipientId: "carol", previousAmount: 0n, newAmount: 50n },
      { recipientId: "bob", previousAmount: 200n, newAmount: 0n },
    ]);
  });

  it("rejects duplicate recipients in a period", () => {
    expect(() =>
      deriveSalaryPolicyChangesFromPeriods(
        makePeriod([
          { recipientId: "alice", amount: 10n },
          { recipientId: "alice", amount: 20n },
        ]),
        makePeriod([])
      )
    ).toThrow(SalaryPolicyImpactValidationError);
  });
});
