import { xdr, nativeToScVal, Keypair } from "@stellar/stellar-sdk";
import {
  createEmptyRecipientLockStatus,
  createMockRecipientLockStatus,
  normalizeRecipientLockStatus,
  fetchRecipientLockStatus,
  evaluateRecipientLockStatus,
  evaluateBatchRecipientLockStatus,
  validateRecipientLockStatus,
  isRecipientLocked,
  canRecipientReceivePayout,
  formatRecipientLockStatus,
  maskRecipientIdentifier,
  maskPayrollIdentifier,
  type ActivePayrollExecution,
} from "../src/payroll/recipientLockStatus";
import { PayrollService } from "../src/payroll";
import { PayrollContractWrapper } from "../src/adapters/PayrollContractWrapper";
import { IProofGenerator } from "../src/crypto/IProofGenerator";

function symbolEntry(key: string, val: xdr.ScVal): xdr.ScMapEntry {
  return new xdr.ScMapEntry({ key: nativeToScVal(key, { type: "symbol" }), val });
}

describe("Payroll Recipient Lock Status Reader (#512)", () => {
  const TEST_RECIPIENT_1 = "GA2C5RFPE6GCKMY3Z4DC6NOURMDRYZ3UMDVQ4N5ACFBPQ4E3Y3376E67";
  const TEST_RECIPIENT_2 = "GBBDU6DDT5I7VO6JCT262L7X3T32NZZ6XUMG575U5K7F5T27YJ3W7WHF";
  const TEST_EMPLOYER = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

  describe("maskRecipientIdentifier and maskPayrollIdentifier", () => {
    it("masks Stellar recipient addresses safely", () => {
      const masked = maskRecipientIdentifier(TEST_RECIPIENT_1);
      expect(masked).toBe("GA2C...6E67");
      expect(masked).not.toBe(TEST_RECIPIENT_1);
    });

    it("masks employee identifiers safely", () => {
      const masked = maskRecipientIdentifier("EMP-12345");
      expect(masked).toBe("EMP***5");
    });

    it("handles empty or short recipient identifiers safely", () => {
      expect(maskRecipientIdentifier("")).toBe("[ANONYMOUS_RECIPIENT]");
      expect(maskRecipientIdentifier(undefined)).toBe("[ANONYMOUS_RECIPIENT]");
      expect(maskRecipientIdentifier("123")).toBe("[REDACTED_RECIPIENT]");
    });

    it("masks payroll identifiers safely", () => {
      expect(maskPayrollIdentifier("payroll-run-2024-01")).toBe("pay...-01");
      expect(maskPayrollIdentifier("")).toBe("[UNKNOWN_PAYROLL]");
      expect(maskPayrollIdentifier("run1")).toBe("[REDACTED_PAYROLL]");
    });
  });

  describe("createEmptyRecipientLockStatus", () => {
    it("creates an unlocked default status with all fields populated", () => {
      const status = createEmptyRecipientLockStatus(TEST_RECIPIENT_1);

      expect(status.recipient).toBe(TEST_RECIPIENT_1);
      expect(status.redactedRecipient).toBe("GA2C...6E67");
      expect(status.isLocked).toBe(false);
      expect(status.canReceivePayout).toBe(true);
      expect(status.lockReason).toBe("none");
      expect(status.payrollId).toBeUndefined();
      expect(status.redactedPayrollId).toBeUndefined();
      expect(status.lockedAt).toBe(0);
      expect(status.unlockAt).toBeUndefined();
      expect(status.lockedBy).toBeUndefined();
      expect(status.fetchedAt).toBeDefined();
    });

    it("supports unredacted recipient when redact: false is specified", () => {
      const status = createEmptyRecipientLockStatus(TEST_RECIPIENT_1, { redact: false });
      expect(status.redactedRecipient).toBe(TEST_RECIPIENT_1);
    });
  });

  describe("createMockRecipientLockStatus", () => {
    it("creates a mock locked status with sensible defaults", () => {
      const mock = createMockRecipientLockStatus();
      expect(mock.isLocked).toBe(true);
      expect(mock.canReceivePayout).toBe(false);
      expect(mock.lockReason).toBe("active_payroll_execution");
      expect(mock.payrollId).toBe("payroll-run-2024-01");
      expect(mock.redactedPayrollId).toBeDefined();
      expect(mock.lockedAt).toBeGreaterThan(0);
      expect(mock.lockedBy).toBeDefined();
    });

    it("allows overriding specific fields", () => {
      const mock = createMockRecipientLockStatus({
        recipient: TEST_RECIPIENT_2,
        isLocked: false,
        lockReason: "none",
        payrollId: undefined,
      });

      expect(mock.recipient).toBe(TEST_RECIPIENT_2);
      expect(mock.isLocked).toBe(false);
      expect(mock.canReceivePayout).toBe(true);
      expect(mock.lockReason).toBe("none");
      expect(mock.payrollId).toBeUndefined();
    });
  });

  describe("normalizeRecipientLockStatus", () => {
    it("returns empty unlocked default for void or non-map responses", () => {
      const status = normalizeRecipientLockStatus(
        xdr.ScVal.scvVoid(),
        TEST_RECIPIENT_1,
        "payroll-100"
      );
      expect(status.isLocked).toBe(false);
      expect(status.canReceivePayout).toBe(true);
      expect(status.recipient).toBe(TEST_RECIPIENT_1);
      expect(status.lockReason).toBe("none");
    });

    it("normalizes boolean responses (e.g. from is_recipient_locked)", () => {
      const lockedVal = xdr.ScVal.scvBool(true);
      const lockedStatus = normalizeRecipientLockStatus(
        lockedVal,
        TEST_RECIPIENT_1,
        "payroll-run-101"
      );
      expect(lockedStatus.isLocked).toBe(true);
      expect(lockedStatus.canReceivePayout).toBe(false);
      expect(lockedStatus.lockReason).toBe("active_payroll_execution");
      expect(lockedStatus.payrollId).toBe("payroll-run-101");
      expect(lockedStatus.redactedPayrollId).toBe("pay...101");

      const unlockedVal = xdr.ScVal.scvBool(false);
      const unlockedStatus = normalizeRecipientLockStatus(
        unlockedVal,
        TEST_RECIPIENT_1,
        "payroll-run-101"
      );
      expect(unlockedStatus.isLocked).toBe(false);
      expect(unlockedStatus.canReceivePayout).toBe(true);
      expect(unlockedStatus.lockReason).toBe("none");
    });

    it("normalizes a complete locked contract map response", () => {
      const raw = xdr.ScVal.scvMap([
        symbolEntry("recipient", nativeToScVal(TEST_RECIPIENT_1, { type: "string" })),
        symbolEntry("is_locked", nativeToScVal(true, { type: "bool" })),
        symbolEntry("payroll_id", nativeToScVal("batch-exec-2024-05", { type: "string" })),
        symbolEntry("locked_at", nativeToScVal("1700000000", { type: "u64" })),
        symbolEntry("unlock_at", nativeToScVal("1700007200", { type: "u64" })),
        symbolEntry(
          "locked_by",
          nativeToScVal("GOPERATORADDR1234567890123456789012345678901234567890123456", {
            type: "string",
          })
        ),
        symbolEntry("lock_reason", nativeToScVal("batch_in_flight", { type: "string" })),
      ]);

      const status = normalizeRecipientLockStatus(raw, TEST_RECIPIENT_1);

      expect(status.isLocked).toBe(true);
      expect(status.canReceivePayout).toBe(false);
      expect(status.recipient).toBe(TEST_RECIPIENT_1);
      expect(status.payrollId).toBe("batch-exec-2024-05");
      expect(status.redactedPayrollId).toBe("bat...-05");
      expect(status.lockReason).toBe("batch_in_flight");
      expect(status.lockedAt).toBe(1700000000 * 1000);
      expect(status.unlockAt).toBe(1700007200 * 1000);
      expect(status.lockedBy).toBe("GOPERATORADDR1234567890123456789012345678901234567890123456");
      expect(status.redactedLockedBy).toBe("GOPE...3456");
    });

    it("falls back to default lock reason when unknown reason string is provided", () => {
      const raw = xdr.ScVal.scvMap([
        symbolEntry("is_locked", nativeToScVal(true, { type: "bool" })),
        symbolEntry("lock_reason", nativeToScVal("custom_unknown_code", { type: "string" })),
      ]);

      const status = normalizeRecipientLockStatus(raw, TEST_RECIPIENT_1);
      expect(status.isLocked).toBe(true);
      expect(status.lockReason).toBe("active_payroll_execution");
    });
  });

  describe("fetchRecipientLockStatus", () => {
    it("throws a structured error when recipient is empty", async () => {
      const mockWrapper = {} as unknown as PayrollContractWrapper;
      const signer = Keypair.random();

      await expect(
        fetchRecipientLockStatus(mockWrapper, "", TEST_EMPLOYER, { signer })
      ).rejects.toMatchObject({
        code: "INVALID_RECIPIENT",
        message: "Recipient address must not be empty.",
      });
    });

    it("invokes contract get_recipient_lock and normalizes response", async () => {
      const mockResult = xdr.ScVal.scvMap([
        symbolEntry("is_locked", nativeToScVal(true, { type: "bool" })),
        symbolEntry("payroll_id", nativeToScVal("run-777", { type: "string" })),
        symbolEntry("locked_at", nativeToScVal("1705000000", { type: "u64" })),
      ]);

      const mockInvoke = jest.fn().mockResolvedValue(mockResult);
      const mockWrapper = { invoke: mockInvoke } as unknown as PayrollContractWrapper;
      const signer = Keypair.random();

      const status = await fetchRecipientLockStatus(mockWrapper, TEST_RECIPIENT_1, TEST_EMPLOYER, {
        signer,
        network: "TESTNET",
        requestId: "req-123",
      });

      expect(mockInvoke).toHaveBeenCalledWith(
        "get_recipient_lock",
        expect.any(Array),
        expect.anything(),
        "TESTNET",
        "req-123"
      );
      expect(status.isLocked).toBe(true);
      expect(status.payrollId).toBe("run-777");
      expect(status.lockedAt).toBe(1705000000 * 1000);
    });

    it("returns an empty default with _error attached on RPC/contract rejection", async () => {
      const mockInvoke = jest.fn().mockRejectedValue(new Error("RPC Timeout"));
      const mockWrapper = { invoke: mockInvoke } as unknown as PayrollContractWrapper;
      const signer = Keypair.random();

      const status = await fetchRecipientLockStatus(mockWrapper, TEST_RECIPIENT_1, TEST_EMPLOYER, {
        signer,
      });

      expect(status.isLocked).toBe(false);
      expect(status.canReceivePayout).toBe(true);
      expect((status as typeof status & { _error?: Error })._error?.message).toBe("RPC Timeout");
    });
  });

  describe("evaluateRecipientLockStatus (pure in-memory evaluation)", () => {
    const activeRuns: ActivePayrollExecution[] = [
      {
        payrollId: "payroll-active-001",
        status: "executing",
        recipients: [TEST_RECIPIENT_1, "GCEXAMPLE1"],
        lockedAt: 1700000000000,
        lockedBy: "GOPERATOR1",
        lockReason: "active_payroll_execution",
      },
      {
        payrollId: "payroll-settling-002",
        status: "pending_settlement",
        recipients: [TEST_RECIPIENT_2],
        lockedAt: 1700005000000,
        lockReason: "pending_settlement",
      },
      {
        payrollId: "payroll-completed-003",
        status: "settled",
        recipients: ["GSETTLEDRECIPIENT"],
      },
      {
        payrollId: "payroll-draft-004",
        status: "draft",
        recipients: ["GDRAFTRECIPIENT"],
      },
    ];

    it("throws on empty recipient identifier", () => {
      expect(() => evaluateRecipientLockStatus("", activeRuns)).toThrow();
    });

    it("returns locked status when recipient is found in an executing run", () => {
      const status = evaluateRecipientLockStatus(TEST_RECIPIENT_1, activeRuns);

      expect(status.isLocked).toBe(true);
      expect(status.canReceivePayout).toBe(false);
      expect(status.lockReason).toBe("active_payroll_execution");
      expect(status.payrollId).toBe("payroll-active-001");
      expect(status.redactedPayrollId).toBe("pay...001");
      expect(status.lockedAt).toBe(1700000000000);
      expect(status.lockedBy).toBe("GOPERATOR1");
      expect(status.redactedLockedBy).toBe("GOPE...TOR1");
    });

    it("returns locked status with correct reason for pending_settlement run", () => {
      const status = evaluateRecipientLockStatus(TEST_RECIPIENT_2, activeRuns);

      expect(status.isLocked).toBe(true);
      expect(status.lockReason).toBe("pending_settlement");
      expect(status.payrollId).toBe("payroll-settling-002");
    });

    it("returns unlocked status when recipient is only in settled or draft runs", () => {
      const statusSettled = evaluateRecipientLockStatus("GSETTLEDRECIPIENT", activeRuns);
      expect(statusSettled.isLocked).toBe(false);
      expect(statusSettled.canReceivePayout).toBe(true);

      const statusDraft = evaluateRecipientLockStatus("GDRAFTRECIPIENT", activeRuns);
      expect(statusDraft.isLocked).toBe(false);
      expect(statusDraft.canReceivePayout).toBe(true);
    });

    it("returns unlocked status when recipient is not part of any active runs", () => {
      const status = evaluateRecipientLockStatus("GUNREGISTEREDRECIPIENT", activeRuns);
      expect(status.isLocked).toBe(false);
      expect(status.canReceivePayout).toBe(true);
    });

    it("handles case-insensitive recipient address matching", () => {
      const status = evaluateRecipientLockStatus(TEST_RECIPIENT_1.toLowerCase(), activeRuns);
      expect(status.isLocked).toBe(true);
    });

    it("edge case: considers lock expired if lockTimeoutMs is exceeded", () => {
      const now = 1700000000000 + 60 * 60 * 1000; // 1 hour after lock
      const statusWithTimeout = evaluateRecipientLockStatus(TEST_RECIPIENT_1, activeRuns, {
        now,
        lockTimeoutMs: 30 * 60 * 1000, // 30 minute timeout
      });

      expect(statusWithTimeout.isLocked).toBe(false);
      expect(statusWithTimeout.canReceivePayout).toBe(true);
    });

    it("edge case: considers lock released if unlockAt has passed", () => {
      const expiringExecution: ActivePayrollExecution = {
        payrollId: "payroll-expiring-005",
        status: "locked",
        recipients: ["GEXPIRINGRECIPIENT"],
        lockedAt: 1000,
        unlockAt: 2000,
      };

      const statusBeforeExpiry = evaluateRecipientLockStatus(
        "GEXPIRINGRECIPIENT",
        [expiringExecution],
        {
          now: 1500,
        }
      );
      expect(statusBeforeExpiry.isLocked).toBe(true);

      const statusAfterExpiry = evaluateRecipientLockStatus(
        "GEXPIRINGRECIPIENT",
        [expiringExecution],
        {
          now: 2500,
        }
      );
      expect(statusAfterExpiry.isLocked).toBe(false);
    });
  });

  describe("evaluateBatchRecipientLockStatus", () => {
    const activeRuns: ActivePayrollExecution[] = [
      {
        payrollId: "payroll-batch-run",
        status: "executing",
        recipients: [TEST_RECIPIENT_1],
        lockedAt: 1700000000000,
      },
    ];

    it("evaluates a batch of recipients and produces aggregate summary", () => {
      const summary = evaluateBatchRecipientLockStatus(
        [TEST_RECIPIENT_1, TEST_RECIPIENT_2, "GUNLOCKEDRECIPIENT"],
        activeRuns
      );

      expect(summary.totalChecked).toBe(3);
      expect(summary.lockedCount).toBe(1);
      expect(summary.unlockedCount).toBe(2);
      expect(summary.hasAnyLocked).toBe(true);
      expect(summary.lockedRecipients).toEqual([TEST_RECIPIENT_1]);
      expect(summary.statuses).toHaveLength(3);
    });

    it("returns hasAnyLocked: false when no recipients are locked", () => {
      const summary = evaluateBatchRecipientLockStatus(
        [TEST_RECIPIENT_2, "GUNLOCKEDRECIPIENT"],
        activeRuns
      );

      expect(summary.totalChecked).toBe(2);
      expect(summary.lockedCount).toBe(0);
      expect(summary.unlockedCount).toBe(2);
      expect(summary.hasAnyLocked).toBe(false);
    });
  });

  describe("validateRecipientLockStatus", () => {
    it("validates a valid locked status", () => {
      const status = createMockRecipientLockStatus();
      const res = validateRecipientLockStatus(status);
      expect(res.ok).toBe(true);
    });

    it("validates a valid unlocked status", () => {
      const status = createEmptyRecipientLockStatus(TEST_RECIPIENT_1);
      const res = validateRecipientLockStatus(status);
      expect(res.ok).toBe(true);
    });

    it("rejects invalid or null objects", () => {
      const resNull = validateRecipientLockStatus(null);
      expect(resNull.ok).toBe(false);

      const resEmpty = validateRecipientLockStatus({ recipient: "" });
      expect(resEmpty.ok).toBe(false);
    });
  });

  describe("isRecipientLocked and canRecipientReceivePayout", () => {
    it("checks lock condition accurately", () => {
      const locked = createMockRecipientLockStatus({ isLocked: true });
      const unlocked = createMockRecipientLockStatus({ isLocked: false });

      expect(isRecipientLocked(locked)).toBe(true);
      expect(canRecipientReceivePayout(locked)).toBe(false);

      expect(isRecipientLocked(unlocked)).toBe(false);
      expect(canRecipientReceivePayout(unlocked)).toBe(true);
    });
  });

  describe("formatRecipientLockStatus", () => {
    it("formats unlocked status with 🔓 badge", () => {
      const unlocked = createEmptyRecipientLockStatus(TEST_RECIPIENT_1);
      const formatted = formatRecipientLockStatus(unlocked);
      expect(formatted).toBe("Recipient GA2C...6E67: 🔓 UNLOCKED (available for payout)");
    });

    it("formats locked status with 🔒 badge and operational details", () => {
      const locked = createMockRecipientLockStatus({
        recipient: TEST_RECIPIENT_1,
        isLocked: true,
        lockReason: "active_payroll_execution",
        payrollId: "run-2024-02",
        lockedAt: Date.UTC(2024, 0, 15, 12, 0, 0),
        lockedBy: "GOPERATOR1234567890123456789012345678901234567890123456",
      });

      const formatted = formatRecipientLockStatus(locked);
      expect(formatted).toBe(
        "Recipient GA2C...6E67: 🔒 LOCKED (active_payroll_execution in run run...-02 by GOPE...3456 since 2024-01-15T12:00:00.000Z)"
      );
    });
  });

  describe("PayrollService integration", () => {
    let service: PayrollService;
    let mockContractWrapper: PayrollContractWrapper;
    let mockProofGenerator: IProofGenerator;
    let signer: Keypair;

    beforeEach(() => {
      signer = Keypair.random();
      mockContractWrapper = {
        invoke: jest.fn(),
      } as unknown as PayrollContractWrapper;
      mockProofGenerator = {
        generateProof: jest.fn(),
      };
      service = new PayrollService(mockContractWrapper, mockProofGenerator, signer);
    });

    it("exposes getRecipientLockStatus on PayrollService instance", async () => {
      const mockResult = xdr.ScVal.scvMap([
        symbolEntry("is_locked", nativeToScVal(true, { type: "bool" })),
        symbolEntry("payroll_id", nativeToScVal("run-service-01", { type: "string" })),
      ]);

      (mockContractWrapper as unknown as Record<string, jest.Mock>)["invoke"].mockResolvedValue(
        mockResult
      );

      const status = await service.getRecipientLockStatus(TEST_RECIPIENT_1, TEST_EMPLOYER);
      expect(status.isLocked).toBe(true);
      expect(status.payrollId).toBe("run-service-01");
      expect(status.canReceivePayout).toBe(false);
    });

    it("exposes pure evaluation and formatting helpers as static and instance methods", () => {
      const activeRuns: ActivePayrollExecution[] = [
        {
          payrollId: "run-999",
          status: "executing",
          recipients: [TEST_RECIPIENT_1],
        },
      ];

      const instanceEval = service.evaluateRecipientLock(TEST_RECIPIENT_1, activeRuns);
      expect(instanceEval.isLocked).toBe(true);

      const staticEval = PayrollService.evaluateRecipientLock(TEST_RECIPIENT_1, activeRuns);
      expect(staticEval.isLocked).toBe(true);

      const batchSummary = PayrollService.evaluateBatchRecipientLock(
        [TEST_RECIPIENT_1, TEST_RECIPIENT_2],
        activeRuns
      );
      expect(batchSummary.totalChecked).toBe(2);
      expect(batchSummary.lockedCount).toBe(1);

      expect(PayrollService.isRecipientLocked(staticEval)).toBe(true);
      expect(PayrollService.canRecipientReceivePayout(staticEval)).toBe(false);

      const formatted = PayrollService.formatRecipientLockStatus(staticEval);
      expect(formatted).toContain("🔒 LOCKED");
    });
  });

  describe("Privacy & Data Protection Guarantees", () => {
    it("never exposes private salary amounts or compensation in lock statuses or formatters", () => {
      const status = createMockRecipientLockStatus();
      const serialized = JSON.stringify(status);

      expect(serialized).not.toContain("amount");
      expect(serialized).not.toContain("salary");
      expect(serialized).not.toContain("wage");
      expect(serialized).not.toContain("stroop");

      const formatted = formatRecipientLockStatus(status);
      expect(formatted).not.toContain("XLM");
      expect(formatted).not.toContain("USDC");
    });

    it("redacts raw recipient addresses in user-facing formatted strings", () => {
      const status = createMockRecipientLockStatus({ recipient: TEST_RECIPIENT_1 });
      const formatted = formatRecipientLockStatus(status);

      expect(formatted).not.toContain(TEST_RECIPIENT_1);
      expect(formatted).toContain("GA2C...6E67");
    });
  });
});
