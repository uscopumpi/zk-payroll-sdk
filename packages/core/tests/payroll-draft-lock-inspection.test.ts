import {
  inspectDraftLock,
  assertDraftLockable,
  isDraftLockable,
  formatDraftLockInspectionSummary,
  createMockDraftLockInspectionResult,
  DraftLockError,
  DraftBuilder,
  PayrollDraft,
  computeDraftChecksum,
} from "../src/draft";
import { PayrollService } from "../src/payroll";
import { PayrollContractWrapper } from "../src/adapters/PayrollContractWrapper";
import { IProofGenerator } from "../src/crypto/IProofGenerator";
import { Keypair } from "@stellar/stellar-sdk";

describe("Payroll Draft Lock Inspection Helper (#537)", () => {
  const RECIPIENT_1 = "GA2C5RFPE6GCKMY3Z4DC6NOURMDRYZ3UMDVQ4N5ACFBPQ4E3Y3376E67";
  const RECIPIENT_2 = "GBBDU6DDT5I7VO6JCT262L7X3T32NZZ6XUMG575U5K7F5T27YJ3W7WHF";
  const RECIPIENT_3 = "GCC5RFPE6GCKMY3Z4DC6NOURMDRYZ3UMDVQ4N5ACFBPQ4E3Y3376E67";

  const validDraft: PayrollDraft = {
    version: 1,
    createdAt: "2024-01-15T10:00:00.000Z",
    updatedAt: "2024-01-15T10:00:00.000Z",
    label: "January-2024-Payroll",
    entries: [
      { recipientId: RECIPIENT_1, amount: "1000000", asset: "native" },
      { recipientId: RECIPIENT_2, amount: "2000000", asset: "native" },
    ],
  };

  describe("inspectDraftLock - Main Path & Lock Readiness", () => {
    it("reports canLock: true and lockState: 'unlocked' for a valid draft", () => {
      const result = inspectDraftLock(validDraft);

      expect(result.canLock).toBe(true);
      expect(result.isLocked).toBe(false);
      expect(result.lockState).toBe("unlocked");
      expect(result.entryCount).toBe(2);
      expect(result.uniqueRecipientCount).toBe(2);
      expect(result.lockedRecipientCount).toBe(0);
      expect(result.lockedRecipients).toEqual([]);
      expect(result.blockers).toHaveLength(0);
      expect(result.summary).toContain("✅ LOCK READY");
      expect(result.checksum).toBeDefined();
    });

    it("accepts a DraftBuilder instance as input", () => {
      const builder = new DraftBuilder(undefined, "Engineering Payroll")
        .add({ recipientId: RECIPIENT_1, amount: "5000", asset: "native" })
        .add({ recipientId: RECIPIENT_2, amount: "7500", asset: "native" });

      const result = inspectDraftLock(builder);
      expect(result.canLock).toBe(true);
      expect(result.entryCount).toBe(2);
      expect(result.draftLabel).toBe("Engineering Payroll");
      expect(result.redactedDraftLabel).toBe("Eng...oll");
    });

    it("accepts a raw array of PayrollDraftEntry items", () => {
      const entries = [{ recipientId: RECIPIENT_1, amount: "100", asset: "USDC" }];

      const result = inspectDraftLock(entries);
      expect(result.canLock).toBe(true);
      expect(result.entryCount).toBe(1);
      expect(result.assets).toEqual(["USDC"]);
    });
  });

  describe("inspectDraftLock - Blockers & Edge Cases", () => {
    it("reports DRAFT_EMPTY blocker when draft has no entries", () => {
      const emptyDraft: PayrollDraft = {
        version: 1,
        createdAt: "2024-01-15T10:00:00.000Z",
        updatedAt: "2024-01-15T10:00:00.000Z",
        entries: [],
      };

      const result = inspectDraftLock(emptyDraft);
      expect(result.canLock).toBe(false);
      expect(result.lockState).toBe("invalid");
      expect(result.blockers).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "DRAFT_EMPTY" })])
      );
      expect(result.summary).toContain("🛑 BLOCKED");
    });

    it("reports DRAFT_ALREADY_LOCKED when isAlreadyLocked is true", () => {
      const result = inspectDraftLock(validDraft, {
        isAlreadyLocked: true,
        lockedAt: 1700000000000,
        lockedBy: "GOPERATOR1",
      });

      expect(result.isLocked).toBe(true);
      expect(result.canLock).toBe(false);
      expect(result.lockState).toBe("locked");
      expect(result.blockers).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "DRAFT_ALREADY_LOCKED" })])
      );
      expect(result.summary).toContain("🔒 LOCKED");
    });

    it("reports DRAFT_EXPIRED when expiresAt timestamp has passed", () => {
      const now = 2000;
      const result = inspectDraftLock(validDraft, {
        now,
        expiresAt: 1000, // expired
      });

      expect(result.canLock).toBe(false);
      expect(result.lockState).toBe("expired");
      expect(result.blockers).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "DRAFT_EXPIRED" })])
      );
      expect(result.summary).toContain("⚠️ EXPIRED");
    });

    it("reports DRAFT_EXPIRED when lockTimeoutMs is exceeded", () => {
      const now = 1700000000000 + 60 * 60 * 1000;
      const result = inspectDraftLock(validDraft, {
        now,
        lockedAt: 1700000000000,
        lockTimeoutMs: 30 * 60 * 1000, // 30 min timeout
      });

      expect(result.canLock).toBe(false);
      expect(result.lockState).toBe("expired");
      expect(result.blockers).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "DRAFT_EXPIRED" })])
      );
    });

    it("validates authorizer permissions against allowedAuthorizers list", () => {
      const unauthorizedResult = inspectDraftLock(validDraft, {
        authorizer: "GUNAUTHORIZED",
        allowedAuthorizers: ["GADMIN1", "GADMIN2"],
      });

      expect(unauthorizedResult.canLock).toBe(false);
      expect(unauthorizedResult.blockers).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "UNAUTHORIZED_LOCKER" })])
      );

      const authorizedResult = inspectDraftLock(validDraft, {
        authorizer: "GADMIN1",
        allowedAuthorizers: ["GADMIN1", "GADMIN2"],
      });
      expect(authorizedResult.canLock).toBe(true);
    });

    it("detects invalid entry fields (empty recipient, invalid amount, missing asset, duplicates)", () => {
      const corruptDraft: PayrollDraft = {
        version: 1,
        createdAt: "2024-01-15T10:00:00.000Z",
        updatedAt: "2024-01-15T10:00:00.000Z",
        entries: [
          { recipientId: "", amount: "100", asset: "native" },
          { recipientId: RECIPIENT_1, amount: "-50", asset: "native" },
          { recipientId: RECIPIENT_1, amount: "200", asset: "" },
        ],
      };

      const result = inspectDraftLock(corruptDraft);
      expect(result.canLock).toBe(false);

      const codes = result.blockers.map((b) => b.code);
      expect(codes).toContain("INVALID_RECIPIENT");
      expect(codes).toContain("INVALID_AMOUNT");
      expect(codes).toContain("MISSING_ASSET");
      expect(codes).toContain("DUPLICATE_RECIPIENT");
    });

    it("verifies expectedChecksum and blocks if checksum mismatch occurs", () => {
      const actualChecksum = computeDraftChecksum(validDraft);

      const matchingResult = inspectDraftLock(validDraft, {
        expectedChecksum: actualChecksum,
      });
      expect(matchingResult.canLock).toBe(true);

      const mismatchResult = inspectDraftLock(validDraft, {
        expectedChecksum: "invalid_tampered_checksum_123456",
      });
      expect(mismatchResult.canLock).toBe(false);
      expect(mismatchResult.blockers).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "CHECKSUM_MISMATCH" })])
      );
    });
  });

  describe("inspectDraftLock - Cross-Checking In-Flight Recipient Locks", () => {
    it("detects when a draft recipient is locked in an active in-flight payroll execution", () => {
      const activeExecutions = [
        {
          payrollId: "run-inflight-001",
          status: "executing",
          recipients: [RECIPIENT_1],
          lockedAt: Date.now() - 5 * 60 * 1000,
        },
      ];

      const result = inspectDraftLock(validDraft, { activeExecutions });

      expect(result.canLock).toBe(false);
      expect(result.lockedRecipientCount).toBe(1);
      expect(result.lockedRecipients).toEqual(["GA2C...6E67"]);
      expect(result.blockers).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            code: "RECIPIENT_LOCKED",
            recipient: "GA2C...6E67",
          }),
        ])
      );
      expect(result.summary).toContain("⚠️ 1 locked");
    });

    it("supports pre-resolved RecipientLockStatus array", () => {
      const recipientLockStatuses = [
        {
          recipient: RECIPIENT_2,
          redactedRecipient: "GBBD...7WHF",
          isLocked: true,
          canReceivePayout: false,
          lockReason: "batch_in_flight" as const,
          payrollId: "batch-789",
          lockedAt: Date.now(),
          fetchedAt: Date.now(),
        },
      ];

      const result = inspectDraftLock(validDraft, { recipientLockStatuses });

      expect(result.canLock).toBe(false);
      expect(result.lockedRecipientCount).toBe(1);
      expect(result.blockers).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            code: "RECIPIENT_LOCKED",
            recipient: "GBBD...7WHF",
          }),
        ])
      );
    });

    it("allows locking when draft recipients are only in settled runs", () => {
      const activeExecutions = [
        {
          payrollId: "run-settled-002",
          status: "settled",
          recipients: [RECIPIENT_1, RECIPIENT_2],
        },
      ];

      const result = inspectDraftLock(validDraft, { activeExecutions });
      expect(result.canLock).toBe(true);
      expect(result.lockedRecipientCount).toBe(0);
    });
  });

  describe("inspectDraftLock - Non-Blocking Warnings", () => {
    it("reports MIXED_ASSETS and LARGE_DRAFT as warnings without blocking lock", () => {
      const mixedDraft: PayrollDraft = {
        version: 1,
        createdAt: "2024-01-15T10:00:00.000Z",
        updatedAt: "2024-01-15T10:00:00.000Z",
        entries: [
          { recipientId: RECIPIENT_1, amount: "100", asset: "native", note: " " },
          { recipientId: RECIPIENT_2, amount: "200", asset: "USDC" },
        ],
      };

      const result = inspectDraftLock(mixedDraft);
      expect(result.canLock).toBe(true);
      expect(result.warnings.length).toBeGreaterThanOrEqual(2);

      const warningCodes = result.warnings.map((w) => w.code);
      expect(warningCodes).toContain("MIXED_ASSETS");
      expect(warningCodes).toContain("EMPTY_NOTE");
    });
  });

  describe("assertDraftLockable and isDraftLockable", () => {
    it("assertDraftLockable does not throw on a valid lockable draft", () => {
      expect(() => assertDraftLockable(validDraft)).not.toThrow();
    });

    it("assertDraftLockable throws a DraftLockError on invalid draft", () => {
      expect(() => assertDraftLockable([])).toThrow(DraftLockError);

      try {
        assertDraftLockable([]);
      } catch (err) {
        expect(err).toBeInstanceOf(DraftLockError);
        const lockErr = err as DraftLockError;
        expect(lockErr.code).toBe("DRAFT_EMPTY");
        expect(lockErr.blockers).toHaveLength(1);
      }
    });

    it("isDraftLockable returns boolean accurately", () => {
      expect(isDraftLockable(validDraft)).toBe(true);
      expect(isDraftLockable([])).toBe(false);
    });
  });

  describe("formatDraftLockInspectionSummary", () => {
    it("formats summary with label, state, entries, recipients, and assets", () => {
      const result = inspectDraftLock(validDraft);
      const formatted = formatDraftLockInspectionSummary(result);

      expect(formatted).toBe(
        "Draft (Jan...oll): ✅ LOCK READY | 2 entries | 2 recipients | assets: native"
      );
    });
  });

  describe("createMockDraftLockInspectionResult", () => {
    it("creates a mock inspection result with overrides", () => {
      const mock = createMockDraftLockInspectionResult({
        canLock: false,
        lockState: "invalid",
        lockedRecipientCount: 2,
      });

      expect(mock.canLock).toBe(false);
      expect(mock.lockState).toBe("invalid");
      expect(mock.lockedRecipientCount).toBe(2);
      expect(mock.entryCount).toBe(2);
    });
  });

  describe("DraftBuilder integration", () => {
    it("exposes inspectLock() and assertLockable() directly on DraftBuilder", () => {
      const builder = new DraftBuilder(undefined, "Q1 Bonus").add({
        recipientId: RECIPIENT_1,
        amount: "1000",
        asset: "native",
      });

      const inspection = builder.inspectLock();
      expect(inspection.canLock).toBe(true);
      expect(inspection.entryCount).toBe(1);

      expect(() => builder.assertLockable()).not.toThrow();

      const emptyBuilder = new DraftBuilder();
      expect(() => emptyBuilder.assertLockable()).toThrow(DraftLockError);
    });
  });

  describe("PayrollService integration", () => {
    let service: PayrollService;

    beforeEach(() => {
      const signer = Keypair.random();
      const mockContractWrapper = {} as unknown as PayrollContractWrapper;
      const mockProofGenerator = { generateProof: jest.fn() } as unknown as IProofGenerator;
      service = new PayrollService(mockContractWrapper, mockProofGenerator, signer);
    });

    it("exposes inspectDraftLock and assertDraftLockable on PayrollService instance", () => {
      const result = service.inspectDraftLock(validDraft);
      expect(result.canLock).toBe(true);

      expect(() => service.assertDraftLockable(validDraft)).not.toThrow();
      expect(() => service.assertDraftLockable([])).toThrow(DraftLockError);
    });

    it("exposes inspectDraftLock and assertDraftLockable as static helpers", () => {
      const result = PayrollService.inspectDraftLock(validDraft);
      expect(result.canLock).toBe(true);

      expect(() => PayrollService.assertDraftLockable(validDraft)).not.toThrow();
    });
  });

  describe("Privacy & Data Protection Guarantees", () => {
    it("never reflects raw salary numbers or amounts in blocker messages", () => {
      const draftWithInvalidEntry: PayrollDraft = {
        version: 1,
        createdAt: "2024-01-15T10:00:00.000Z",
        updatedAt: "2024-01-15T10:00:00.000Z",
        entries: [
          { recipientId: RECIPIENT_1, amount: "9999999999", asset: "" }, // missing asset
        ],
      };

      const result = inspectDraftLock(draftWithInvalidEntry);
      const json = JSON.stringify(result.blockers);

      expect(json).not.toContain("9999999999");
      expect(json).not.toContain("salary");
      expect(json).not.toContain("wage");
      expect(json).not.toContain("compensation");
    });

    it("redacts raw recipient addresses in blockers and locked recipient lists", () => {
      const activeExecutions = [
        {
          payrollId: "run-999",
          status: "executing",
          recipients: [RECIPIENT_1],
        },
      ];

      const result = inspectDraftLock(validDraft, { activeExecutions });

      expect(result.lockedRecipients).not.toContain(RECIPIENT_1);
      expect(result.lockedRecipients).toContain("GA2C...6E67");

      const blockerMsg = result.blockers.find((b) => b.code === "RECIPIENT_LOCKED")?.message;
      expect(blockerMsg).not.toContain(RECIPIENT_1);
      expect(blockerMsg).toContain("GA2C...6E67");
    });
  });
});
