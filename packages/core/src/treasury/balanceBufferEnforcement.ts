/**
 * Treasury Balance Buffer Enforcement
 *
 * Implements SDK-level validation to enforce minimum liquidity buffers
 * in the treasury prior to committing payroll disbursements or reserves (Issue #706).
 *
 * Prevents transaction failure from slippage, gas depletion, operational cash-flow
 * starvation, and negative unreserved balances by verifying that post-payout treasury
 * reserves satisfy both absolute minimums and percentage-based liquidity thresholds.
 *
 * @module
 */

/**
 * Configuration options governing the treasury liquidity buffer.
 */
export interface BufferEnforcementPolicy {
  /** Absolute minimum balance that must remain in treasury at all times (in base units). */
  minBufferAmount?: bigint;
  /** Percentage-based buffer on top of obligations, in basis points (1 bp = 0.01%, 500 bp = 5%). */
  bufferPercentageBasisPoints?: number;
  /** Roles exempted from buffer enforcement during emergency overrides. */
  exemptRoles?: string[];
  /** Whether emergency overrides are permitted. */
  allowEmergencyOverride?: boolean;
}

/**
 * Request to check and enforce treasury balance buffers before dispatch.
 */
export interface TreasuryBufferCheckRequest {
  /** Asset identifier (e.g. "native", "USDC:G...", contract address). */
  asset: string;
  /** Total current treasury on-chain balance for this asset (in base units). */
  currentTreasuryBalance: bigint;
  /** Portions of balance already locked or earmarked for other reservations. */
  reservedBalance?: bigint;
  /** Total obligation amount requested for payout or commitment. */
  pendingPayoutAmount: bigint;
  /** Optional role of the actor requesting the disbursement. */
  requesterRole?: string;
  /** Optional emergency override flag. */
  isEmergencyOverride?: boolean;
  /** Optional custom policy overriding global settings. */
  policy?: BufferEnforcementPolicy;
}

/** Error codes emitted on buffer breach or calculation failure. */
export type TreasuryBufferDenialCode =
  | "BUFFER_BREACHED"
  | "INSUFFICIENT_TREASURY_BALANCE"
  | "NEGATIVE_BALANCE"
  | "INVALID_AMOUNTS"
  | "UNAUTHORIZED_OVERRIDE";

/**
 * Detailed outcome of evaluating treasury liquidity buffer compliance.
 */
export interface TreasuryBufferEnforcementResult {
  /** True if payout may proceed safely without breaching required liquidity buffers. */
  compliant: boolean;
  /** Target asset evaluated. */
  asset: string;
  /** Total current balance before execution. */
  currentBalance: bigint;
  /** Balance available for operations (currentBalance - reservedBalance). */
  usableBalance: bigint;
  /** Required liquidity buffer that must be preserved. */
  requiredBuffer: bigint;
  /** Requested payout amount. */
  pendingPayoutAmount: bigint;
  /** Projected post-payout unreserved balance (usableBalance - pendingPayoutAmount). */
  projectedRemainingBalance: bigint;
  /** Non-zero shortfall amount if compliant is false. */
  shortfallAmount: bigint;
  /** Denial code if compliant is false. */
  denialCode?: TreasuryBufferDenialCode;
  /** Privacy-preserving, actionable explanatory message. */
  reason: string;
  /** Advisory warnings for low-buffer conditions. */
  warnings: string[];
}

/** Error class thrown by assertTreasuryBalanceBuffer. */
export class TreasuryBalanceBufferError extends Error {
  public readonly code: TreasuryBufferDenialCode;
  public readonly asset: string;
  public readonly shortfallAmount: bigint;

  constructor(
    message: string,
    code: TreasuryBufferDenialCode,
    asset: string,
    shortfallAmount: bigint = 0n
  ) {
    super(message);
    this.name = "TreasuryBalanceBufferError";
    this.code = code;
    this.asset = asset;
    this.shortfallAmount = shortfallAmount;
  }
}

export const DEFAULT_BUFFER_POLICY: BufferEnforcementPolicy = {
  minBufferAmount: 1000n, // Default absolute minimum stroops/units
  bufferPercentageBasisPoints: 500, // 5% reserve buffer
  exemptRoles: ["EMERGENCY_ADMIN", "SUPER_ADMIN"],
  allowEmergencyOverride: true,
};

/**
 * Calculates the required liquidity buffer amount for a given obligation amount.
 * The buffer is the MAXIMUM of the absolute floor and the percentage-based buffer.
 */
export function calculateRequiredBuffer(
  payoutAmount: bigint,
  policy: BufferEnforcementPolicy = DEFAULT_BUFFER_POLICY
): bigint {
  const minFloor = policy.minBufferAmount ?? 0n;
  const bps = BigInt(policy.bufferPercentageBasisPoints ?? 0);

  // percentageBuffer = (payoutAmount * bps) / 10000n
  const percentageBuffer = (payoutAmount * bps) / 10000n;

  return percentageBuffer > minFloor ? percentageBuffer : minFloor;
}

/**
 * Enforces treasury balance buffer requirements against an impending payout.
 */
export function enforceTreasuryBalanceBuffer(
  request: TreasuryBufferCheckRequest,
  defaultPolicy: BufferEnforcementPolicy = DEFAULT_BUFFER_POLICY
): TreasuryBufferEnforcementResult {
  const {
    asset,
    currentTreasuryBalance,
    reservedBalance = 0n,
    pendingPayoutAmount,
    requesterRole,
    isEmergencyOverride = false,
  } = request;

  const warnings: string[] = [];
  const policy = { ...defaultPolicy, ...(request.policy ?? {}) };

  // 1. Validate negative/invalid amounts
  if (currentTreasuryBalance < 0n || reservedBalance < 0n || pendingPayoutAmount < 0n) {
    return {
      compliant: false,
      asset,
      currentBalance: currentTreasuryBalance,
      usableBalance: 0n,
      requiredBuffer: 0n,
      pendingPayoutAmount,
      projectedRemainingBalance: 0n,
      shortfallAmount: 0n,
      denialCode: "INVALID_AMOUNTS",
      reason: "Treasury balance, reserved balance, and payout amount must be non-negative bigints.",
      warnings,
    };
  }

  const usableBalance = currentTreasuryBalance - reservedBalance;
  if (usableBalance < 0n) {
    return {
      compliant: false,
      asset,
      currentBalance: currentTreasuryBalance,
      usableBalance,
      requiredBuffer: 0n,
      pendingPayoutAmount,
      projectedRemainingBalance: usableBalance - pendingPayoutAmount,
      shortfallAmount: -usableBalance + pendingPayoutAmount,
      denialCode: "NEGATIVE_BALANCE",
      reason: `Treasury active reservations (${reservedBalance}) exceed total balance (${currentTreasuryBalance}).`,
      warnings,
    };
  }

  // 2. Check emergency override exemption
  if (isEmergencyOverride) {
    const exemptRoles = (policy.exemptRoles ?? []).map((r) => r.toUpperCase());
    const role = (requesterRole ?? "").trim().toUpperCase();
    if (!policy.allowEmergencyOverride || !exemptRoles.includes(role)) {
      return {
        compliant: false,
        asset,
        currentBalance: currentTreasuryBalance,
        usableBalance,
        requiredBuffer: 0n,
        pendingPayoutAmount,
        projectedRemainingBalance: usableBalance - pendingPayoutAmount,
        shortfallAmount: 0n,
        denialCode: "UNAUTHORIZED_OVERRIDE",
        reason: `Role "${requesterRole ?? "[empty]"}" is not authorized for emergency buffer override.`,
        warnings,
      };
    }

    // Emergency override granted: check basic solvency (payout <= usableBalance)
    if (pendingPayoutAmount > usableBalance) {
      const shortfall = pendingPayoutAmount - usableBalance;
      return {
        compliant: false,
        asset,
        currentBalance: currentTreasuryBalance,
        usableBalance,
        requiredBuffer: 0n,
        pendingPayoutAmount,
        projectedRemainingBalance: usableBalance - pendingPayoutAmount,
        shortfallAmount: shortfall,
        denialCode: "INSUFFICIENT_TREASURY_BALANCE",
        reason: `Emergency override permitted, but usable balance (${usableBalance}) cannot cover payout (${pendingPayoutAmount}).`,
        warnings,
      };
    }

    warnings.push("Treasury buffer check bypassed via authorized emergency override.");
    return {
      compliant: true,
      asset,
      currentBalance: currentTreasuryBalance,
      usableBalance,
      requiredBuffer: 0n,
      pendingPayoutAmount,
      projectedRemainingBalance: usableBalance - pendingPayoutAmount,
      shortfallAmount: 0n,
      reason: `Emergency override authorized for role ${role}. Payout permitted.`,
      warnings,
    };
  }

  // 3. Normal Buffer Enforcement
  const requiredBuffer = calculateRequiredBuffer(pendingPayoutAmount, policy);
  const totalRequired = pendingPayoutAmount + requiredBuffer;
  const projectedRemaining = usableBalance - pendingPayoutAmount;

  // Basic balance sufficiency check
  if (pendingPayoutAmount > usableBalance) {
    const shortfall = pendingPayoutAmount - usableBalance;
    return {
      compliant: false,
      asset,
      currentBalance: currentTreasuryBalance,
      usableBalance,
      requiredBuffer,
      pendingPayoutAmount,
      projectedRemainingBalance: projectedRemaining,
      shortfallAmount: shortfall,
      denialCode: "INSUFFICIENT_TREASURY_BALANCE",
      reason: `Treasury usable balance (${usableBalance} ${asset}) is less than required payout (${pendingPayoutAmount} ${asset}).`,
      warnings,
    };
  }

  // Buffer compliance check
  if (projectedRemaining < requiredBuffer) {
    const shortfall = requiredBuffer - projectedRemaining;
    return {
      compliant: false,
      asset,
      currentBalance: currentTreasuryBalance,
      usableBalance,
      requiredBuffer,
      pendingPayoutAmount,
      projectedRemainingBalance: projectedRemaining,
      shortfallAmount: shortfall,
      denialCode: "BUFFER_BREACHED",
      reason: `Disbursement leaves ${projectedRemaining} ${asset}, breaching the required liquidity buffer of ${requiredBuffer} ${asset} (shortfall: ${shortfall}).`,
      warnings,
    };
  }

  // Warning when balance is close to buffer boundary (within 10% of buffer above minimum)
  const marginAboveBuffer = projectedRemaining - requiredBuffer;
  if (marginAboveBuffer > 0n && marginAboveBuffer < requiredBuffer / 10n) {
    warnings.push(`Projected treasury balance post-payout is close to minimum buffer threshold.`);
  }

  return {
    compliant: true,
    asset,
    currentBalance: currentTreasuryBalance,
    usableBalance,
    requiredBuffer,
    pendingPayoutAmount,
    projectedRemainingBalance: projectedRemaining,
    shortfallAmount: 0n,
    reason: `Treasury balance covers payout (${pendingPayoutAmount} ${asset}) while preserving required buffer (${requiredBuffer} ${asset}).`,
    warnings,
  };
}

/**
 * Asserts treasury buffer compliance, throwing TreasuryBalanceBufferError if non-compliant.
 */
export function assertTreasuryBalanceBuffer(
  request: TreasuryBufferCheckRequest,
  defaultPolicy?: BufferEnforcementPolicy
): TreasuryBufferEnforcementResult {
  const result = enforceTreasuryBalanceBuffer(request, defaultPolicy);
  if (!result.compliant) {
    throw new TreasuryBalanceBufferError(
      result.reason,
      result.denialCode ?? "BUFFER_BREACHED",
      result.asset,
      result.shortfallAmount
    );
  }
  return result;
}
