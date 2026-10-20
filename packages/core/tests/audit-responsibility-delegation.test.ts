import {
  auditPayrollResponsibilityDelegation,
  assertPayrollResponsibilityDelegation,
  validatePayrollDelegationRecord,
  maskAddress,
  PayrollDelegationAuditError,
  type PayrollDelegationRecord,
  type PayrollDelegationAuditRequest,
} from "../src/audit/responsibilityDelegationAudit";

describe("Payroll Responsibility Delegation Audit (#708)", () => {
  const delegator = "GADMINAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH";
  const delegate = "GDELEGATEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBH";
  const baseNow = 1700000000000; // Fixed epoch time

  const validRecord: PayrollDelegationRecord = {
    delegationId: "del-001",
    delegator,
    delegate,
    responsibilities: ["BATCH_SUBMISSION", "RECONCILIATION"],
    validFromMs: baseNow - 100000,
    validToMs: baseNow + 100000,
  };

  describe("validatePayrollDelegationRecord", () => {
    it("validates a well-formed delegation record", () => {
      const result = validatePayrollDelegationRecord(validRecord);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("rejects when delegator equals delegate", () => {
      const result = validatePayrollDelegationRecord({
        ...validRecord,
        delegate: delegator,
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Delegator and delegate cannot be the same address.");
    });

    it("rejects when validFromMs is after validToMs", () => {
      const result = validatePayrollDelegationRecord({
        ...validRecord,
        validFromMs: baseNow + 5000,
        validToMs: baseNow - 5000,
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("validFromMs must precede validToMs.");
    });

    it("rejects empty responsibilities list", () => {
      const result = validatePayrollDelegationRecord({
        ...validRecord,
        responsibilities: [],
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        "Responsibilities list must contain at least one valid responsibility."
      );
    });
  });

  describe("auditPayrollResponsibilityDelegation", () => {
    it("authorizes a valid delegation for granted responsibility (success path)", () => {
      const request: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "BATCH_SUBMISSION",
        delegate,
        timestampMs: baseNow,
      };

      const decision = auditPayrollResponsibilityDelegation(request, validRecord, baseNow);
      expect(decision.authorized).toBe(true);
      expect(decision.denialCode).toBeUndefined();
      expect(decision.reason).toContain('is authorized for "BATCH_SUBMISSION"');
    });

    it("denies when claimed responsibility is not in granted list (failure path)", () => {
      const request: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "SALARY_UPDATE", // Not granted
        delegate,
        timestampMs: baseNow,
      };

      const decision = auditPayrollResponsibilityDelegation(request, validRecord, baseNow);
      expect(decision.authorized).toBe(false);
      expect(decision.denialCode).toBe("UNAUTHORIZED_RESPONSIBILITY");
      expect(decision.reason).toContain('does not include responsibility "SALARY_UPDATE"');
    });

    it("denies when actor is not the designated delegate (failure path)", () => {
      const request: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "BATCH_SUBMISSION",
        delegate: "GRANDOMLYDIFFERENTPERSONCCCCCCCCCCCCCCCCCCCCCCCCCCCCCH",
        timestampMs: baseNow,
      };

      const decision = auditPayrollResponsibilityDelegation(request, validRecord, baseNow);
      expect(decision.authorized).toBe(false);
      expect(decision.denialCode).toBe("DELEGATE_MISMATCH");
    });

    it("denies when delegation has expired (failure path)", () => {
      const request: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "BATCH_SUBMISSION",
        delegate,
        timestampMs: baseNow + 200000, // Past validToMs
      };

      const decision = auditPayrollResponsibilityDelegation(request, validRecord, baseNow);
      expect(decision.authorized).toBe(false);
      expect(decision.denialCode).toBe("DELEGATION_EXPIRED");
    });

    it("denies when delegation is not yet active (edge case: premature execution)", () => {
      const request: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "BATCH_SUBMISSION",
        delegate,
        timestampMs: baseNow - 200000, // Before validFromMs
      };

      const decision = auditPayrollResponsibilityDelegation(request, validRecord, baseNow);
      expect(decision.authorized).toBe(false);
      expect(decision.denialCode).toBe("DELEGATION_NOT_YET_ACTIVE");
    });

    it("denies when delegation was revoked (edge case)", () => {
      const revokedRecord: PayrollDelegationRecord = {
        ...validRecord,
        revoked: true,
        revokedAtMs: baseNow - 1000,
        revocationReason: "Role reassignment",
      };

      const request: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "BATCH_SUBMISSION",
        delegate,
        timestampMs: baseNow,
      };

      const decision = auditPayrollResponsibilityDelegation(request, revokedRecord, baseNow);
      expect(decision.authorized).toBe(false);
      expect(decision.denialCode).toBe("DELEGATION_REVOKED");
      expect(decision.reason).toContain("Role reassignment");
    });

    it("denies when delegation record is missing entirely", () => {
      const request: PayrollDelegationAuditRequest = {
        delegationId: "non-existent",
        claimedResponsibility: "BATCH_SUBMISSION",
        delegate,
      };

      const decision = auditPayrollResponsibilityDelegation(request, null, baseNow);
      expect(decision.authorized).toBe(false);
      expect(decision.denialCode).toBe("NO_ACTIVE_DELEGATION");
    });
  });

  describe("assertPayrollResponsibilityDelegation", () => {
    it("returns decision on success and throws typed error on failure", () => {
      const validReq: PayrollDelegationAuditRequest = {
        delegationId: "del-001",
        claimedResponsibility: "RECONCILIATION",
        delegate,
        timestampMs: baseNow,
      };

      expect(() =>
        assertPayrollResponsibilityDelegation(validReq, validRecord, baseNow)
      ).not.toThrow();

      const invalidReq: PayrollDelegationAuditRequest = {
        ...validReq,
        claimedResponsibility: "EMERGENCY_ACTIONS",
      };

      expect(() => assertPayrollResponsibilityDelegation(invalidReq, validRecord, baseNow)).toThrow(
        PayrollDelegationAuditError
      );
    });
  });

  describe("maskAddress privacy utility", () => {
    it("masks long public keys while preserving endpoints", () => {
      expect(maskAddress(delegator)).toBe("GADM...AAAH");
      expect(maskAddress("SHORT")).toBe("SHORT");
      expect(maskAddress(undefined)).toBe("[UNKNOWN]");
    });
  });
});
