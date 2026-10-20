import {
  validatePeriodReopening,
  assertPeriodReopeningAllowed,
  PeriodReopeningRestrictionError,
  type PayrollPeriodRecord,
  type PeriodReopeningRequest,
} from "../src/payroll/periodReopeningRestrictions";

describe("Payroll Period Reopening Restrictions (#707)", () => {
  const baseNow = 1710000000000; // Fixed epoch time
  const closedPeriod: PayrollPeriodRecord = {
    periodId: "2026-03",
    state: "closed",
    closedAtMs: baseNow - 5 * 24 * 60 * 60 * 1000, // Closed 5 days ago
    reopenCount: 0,
    maxAllowedReopens: 2,
    lockoutWindowMs: 30 * 24 * 60 * 60 * 1000, // 30 days
  };

  const validRequest: PeriodReopeningRequest = {
    periodId: "2026-03",
    requester: "GAPAYROLLADMIN11111111111111111111111111111111111111111H",
    requesterRole: "PAYROLL_ADMIN",
    approver: "GCOMPLIANCEOFFICER22222222222222222222222222222222222H",
    approverRole: "COMPLIANCE_OFFICER",
    reason: "COMPLIANCE_CORRECTION",
    justification: "Correction of overtime tax calculation following statutory rate adjustment.",
    requestedAtMs: baseNow,
  };

  it("permits reopening for authorized dual-control request on closed period (success path)", () => {
    const result = validatePeriodReopening(validRequest, closedPeriod, {}, baseNow);
    expect(result.allowed).toBe(true);
    expect(result.denialCode).toBeUndefined();
    expect(result.auditRecord).toBeDefined();
    expect(result.auditRecord?.reopenCountNext).toBe(1);
  });

  it("rejects when period is in immutable 'audited' state (failure path)", () => {
    const auditedPeriod: PayrollPeriodRecord = {
      ...closedPeriod,
      state: "audited",
    };

    const result = validatePeriodReopening(validRequest, auditedPeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("PERIOD_IMMUTABLE_AUDITED");
    expect(result.reason).toContain("formally audited and sealed");
  });

  it("rejects when period is already 'open' or 'reopened'", () => {
    const activePeriod: PayrollPeriodRecord = {
      ...closedPeriod,
      state: "open",
    };

    const result = validatePeriodReopening(validRequest, activePeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("PERIOD_ALREADY_ACTIVE");
  });

  it("rejects when maximum allowed reopen threshold is reached (failure path)", () => {
    const maxedPeriod: PayrollPeriodRecord = {
      ...closedPeriod,
      reopenCount: 2,
      maxAllowedReopens: 2,
    };

    const result = validatePeriodReopening(validRequest, maxedPeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("MAX_REOPENS_EXCEEDED");
    expect(result.reason).toContain("maximum allowed reopening limit");
  });

  it("rejects when lockout window elapsed since closure (failure path)", () => {
    const expiredPeriod: PayrollPeriodRecord = {
      ...closedPeriod,
      closedAtMs: baseNow - 40 * 24 * 60 * 60 * 1000, // 40 days ago (> 30 days)
    };

    const result = validatePeriodReopening(validRequest, expiredPeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("LOCKOUT_WINDOW_EXPIRED");
  });

  it("rejects self-approval under dual control policy (edge case)", () => {
    const selfApprovalRequest: PeriodReopeningRequest = {
      ...validRequest,
      approver: validRequest.requester, // Same actor!
    };

    const result = validatePeriodReopening(selfApprovalRequest, closedPeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("SELF_APPROVAL_DISALLOWED");
    expect(result.reason).toContain("Self-approval is prohibited");
  });

  it("rejects when justification is too short or empty (edge case)", () => {
    const weakJustificationReq: PeriodReopeningRequest = {
      ...validRequest,
      justification: "Fix bug", // Too short (< 15 chars)
    };

    const result = validatePeriodReopening(weakJustificationReq, closedPeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("INSUFFICIENT_JUSTIFICATION");
  });

  it("rejects unauthorized requester role", () => {
    const unauthorizedReq: PeriodReopeningRequest = {
      ...validRequest,
      requesterRole: "INTERN",
    };

    const result = validatePeriodReopening(unauthorizedReq, closedPeriod, {}, baseNow);
    expect(result.allowed).toBe(false);
    expect(result.denialCode).toBe("UNAUTHORIZED_REQUESTER_ROLE");
  });

  it("assertPeriodReopeningAllowed throws typed error on rejection", () => {
    const invalidReq: PeriodReopeningRequest = {
      ...validRequest,
      requesterRole: "INTERN",
    };

    expect(() => assertPeriodReopeningAllowed(invalidReq, closedPeriod, {}, baseNow)).toThrow(
      PeriodReopeningRestrictionError
    );
  });
});
