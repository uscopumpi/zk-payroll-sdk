import {
  enforceTreasuryBalanceBuffer,
  assertTreasuryBalanceBuffer,
  calculateRequiredBuffer,
  TreasuryBalanceBufferError,
  type TreasuryBufferCheckRequest,
} from "../src/treasury/balanceBufferEnforcement";

describe("Treasury Balance Buffer Enforcement (#706)", () => {
  const asset = "USDC";

  describe("calculateRequiredBuffer", () => {
    it("returns absolute minimum buffer when percentage buffer is lower", () => {
      // 5% of 1000 is 50, but min buffer is 1000
      const buffer = calculateRequiredBuffer(1000n, {
        minBufferAmount: 1000n,
        bufferPercentageBasisPoints: 500, // 5%
      });
      expect(buffer).toBe(1000n);
    });

    it("returns percentage-based buffer when it exceeds minimum floor", () => {
      // 5% of 100_000 is 5_000, which exceeds min floor of 1000
      const buffer = calculateRequiredBuffer(100_000n, {
        minBufferAmount: 1000n,
        bufferPercentageBasisPoints: 500, // 5%
      });
      expect(buffer).toBe(5000n);
    });
  });

  describe("enforceTreasuryBalanceBuffer", () => {
    it("permits payout when treasury covers payout plus required buffer (success path)", () => {
      const request: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 200_000n,
        reservedBalance: 20_000n, // Usable: 180_000
        pendingPayoutAmount: 50_000n, // Buffer (5%): 2500 -> Required: 52_500
        policy: {
          minBufferAmount: 1000n,
          bufferPercentageBasisPoints: 500,
        },
      };

      const result = enforceTreasuryBalanceBuffer(request);
      expect(result.compliant).toBe(true);
      expect(result.denialCode).toBeUndefined();
      expect(result.usableBalance).toBe(180_000n);
      expect(result.projectedRemainingBalance).toBe(130_000n);
      expect(result.requiredBuffer).toBe(2500n);
    });

    it("rejects payout when remaining balance breaches the required buffer (failure path)", () => {
      const request: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 51_000n,
        reservedBalance: 0n,
        pendingPayoutAmount: 50_000n,
        policy: {
          minBufferAmount: 2000n, // Required buffer: 2500 (5%)
          bufferPercentageBasisPoints: 500,
        },
      };

      const result = enforceTreasuryBalanceBuffer(request);
      expect(result.compliant).toBe(false);
      expect(result.denialCode).toBe("BUFFER_BREACHED");
      expect(result.projectedRemainingBalance).toBe(1000n);
      expect(result.requiredBuffer).toBe(2500n);
      expect(result.shortfallAmount).toBe(1500n); // 2500 - 1000
      expect(result.reason).toContain("breaching the required liquidity buffer");
    });

    it("rejects payout when usable balance cannot even cover payout obligation (failure path)", () => {
      const request: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 40_000n,
        reservedBalance: 5_000n, // Usable: 35_000
        pendingPayoutAmount: 50_000n,
      };

      const result = enforceTreasuryBalanceBuffer(request);
      expect(result.compliant).toBe(false);
      expect(result.denialCode).toBe("INSUFFICIENT_TREASURY_BALANCE");
      expect(result.shortfallAmount).toBe(15_000n);
    });

    it("permits emergency override for authorized emergency role (edge case)", () => {
      const emergencyRequest: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 51_000n,
        reservedBalance: 0n,
        pendingPayoutAmount: 50_000n, // Leaves 1000, normally fails 2500 buffer
        isEmergencyOverride: true,
        requesterRole: "EMERGENCY_ADMIN",
        policy: {
          minBufferAmount: 2500n,
          exemptRoles: ["EMERGENCY_ADMIN"],
          allowEmergencyOverride: true,
        },
      };

      const result = enforceTreasuryBalanceBuffer(emergencyRequest);
      expect(result.compliant).toBe(true);
      expect(result.warnings).toContain(
        "Treasury buffer check bypassed via authorized emergency override."
      );
    });

    it("rejects emergency override for unauthorized role (edge case)", () => {
      const unauthorizedOverride: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 51_000n,
        pendingPayoutAmount: 50_000n,
        isEmergencyOverride: true,
        requesterRole: "GUEST_USER",
      };

      const result = enforceTreasuryBalanceBuffer(unauthorizedOverride);
      expect(result.compliant).toBe(false);
      expect(result.denialCode).toBe("UNAUTHORIZED_OVERRIDE");
    });

    it("rejects negative balances or amounts", () => {
      const negativeReq: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: -100n,
        pendingPayoutAmount: 500n,
      };

      const result = enforceTreasuryBalanceBuffer(negativeReq);
      expect(result.compliant).toBe(false);
      expect(result.denialCode).toBe("INVALID_AMOUNTS");
    });
  });

  describe("assertTreasuryBalanceBuffer", () => {
    it("returns result on success and throws typed error on breach", () => {
      const validReq: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 10_000n,
        pendingPayoutAmount: 1_000n,
      };

      expect(() => assertTreasuryBalanceBuffer(validReq)).not.toThrow();

      const invalidReq: TreasuryBufferCheckRequest = {
        asset,
        currentTreasuryBalance: 1_500n,
        pendingPayoutAmount: 1_000n,
        policy: { minBufferAmount: 1000n }, // Needs 2000 total, only has 1500
      };

      expect(() => assertTreasuryBalanceBuffer(invalidReq)).toThrow(TreasuryBalanceBufferError);
    });
  });
});
