/**
 * Payroll Period Reopening Restrictions
 *
 * Implements SDK-level validation and policy controls for reopening closed,
 * finalized, or audited payroll periods (Issue #707).
 *
 * Prevents unauthorized or uncoordinated historical accounting modifications,
 * enforces dual-control approval, caps maximum reopen attempts, and rejects
 * reopening once periods enter immutable audited locks or exceed policy lockout windows.
 *
 * @module
 */

/**
 * Recognized lifecycle states of a payroll accounting period.
 */
export type PayrollPeriodLifecycleState =
  "draft" | "open" | "closed" | "finalized" | "reopened" | "audited";

/**
 * Valid business reasons permitted to justify a period reopening.
 */
export type PeriodReopeningReason =
  | "TAX_ADJUSTMENT"
  | "COMPLIANCE_CORRECTION"
  | "PAYMENT_FAILURE_REMEDY"
  | "DISPUTE_SETTLEMENT"
  | "MANUAL_OVERRIDE";

export const PERMITTED_REOPENING_REASONS: readonly PeriodReopeningReason[] = [
  "TAX_ADJUSTMENT",
  "COMPLIANCE_CORRECTION",
  "PAYMENT_FAILURE_REMEDY",
  "DISPUTE_SETTLEMENT",
  "MANUAL_OVERRIDE",
];

/**
 * Current state and historical metrics of a payroll period.
 */
export interface PayrollPeriodRecord {
  /** Identifier of the payroll period (e.g. "2026-Q1" or "2026-03"). */
  periodId: string;
  /** Current lifecycle status. */
  state: PayrollPeriodLifecycleState;
  /** Timestamp when the period was initially closed (epoch ms). */
  closedAtMs?: number;
  /** Timestamp when the period was finalized (epoch ms). */
  finalizedAtMs?: number;
  /** Number of times this period has previously been reopened. */
  reopenCount: number;
  /** Maximum number of reopens allowed for this specific period (defaults to policy max). */
  maxAllowedReopens?: number;
  /** Duration in ms after closure beyond which reopening is prohibited. */
  lockoutWindowMs?: number;
}

/**
 * Request to reopen a non-active payroll period.
 */
export interface PeriodReopeningRequest {
  /** The target period to reopen. */
  periodId: string;
  /** Address or identifier of the administrative actor requesting reopening. */
  requester: string;
  /** Operational role held by the requester (e.g., "PAYROLL_ADMIN", "COMPLIANCE_OFFICER"). */
  requesterRole: string;
  /** Second authorized actor approving the reopening under dual-control policy. */
  approver?: string;
  /** Operational role of the second approving actor. */
  approverRole?: string;
  /** Formal business classification for the reopening request. */
  reason: PeriodReopeningReason;
  /** Descriptive written justification detailing why the change is necessary. */
  justification: string;
  /** Epoch timestamp of the request submission. */
  requestedAtMs?: number;
}

/**
 * Configurable organizational restrictions on period reopening.
 */
export interface PeriodReopeningPolicyOptions {
  /** Roles authorized to initiate a reopening (default: ["PAYROLL_ADMIN", "SUPER_ADMIN"]). */
  authorizedRoles?: string[];
  /** Roles authorized to co-approve under dual-control (default: ["COMPLIANCE_OFFICER", "FINANCE_DIRECTOR", "SUPER_ADMIN"]). */
  authorizedApproverRoles?: string[];
  /** Whether dual-control (requester != approver) is mandatory (default: true). */
  requireDualControl?: boolean;
  /** Global maximum times a single period may be reopened (default: 2). */
  maxReopenCount?: number;
  /** Maximum duration in ms after closure after which reopening is hard-locked (default: 30 days). */
  lockoutWindowMs?: number;
  /** Minimum character length required for justification string (default: 15). */
  minJustificationLength?: number;
}

/** Reason codes for rejected period reopening attempts. */
export type PeriodReopeningDenialCode =
  | "PERIOD_NOT_FOUND"
  | "PERIOD_ALREADY_ACTIVE"
  | "PERIOD_IMMUTABLE_AUDITED"
  | "MAX_REOPENS_EXCEEDED"
  | "LOCKOUT_WINDOW_EXPIRED"
  | "UNAUTHORIZED_REQUESTER_ROLE"
  | "UNAUTHORIZED_APPROVER_ROLE"
  | "DUAL_CONTROL_REQUIRED"
  | "SELF_APPROVAL_DISALLOWED"
  | "INVALID_REASON"
  | "INSUFFICIENT_JUSTIFICATION"
  | "INVALID_REQUEST";

/**
 * Decision result from validating a period reopening request.
 */
export interface PeriodReopeningValidationResult {
  /** True when all reopening conditions, authorizations, and safety bounds are met. */
  allowed: boolean;
  /** Identifier of the evaluated period. */
  periodId: string;
  /** Specific denial code if rejected. */
  denialCode?: PeriodReopeningDenialCode;
  /** Privacy-safe human-readable rationale. */
  reason: string;
  /** Non-fatal advisory notices. */
  warnings: string[];
  /** Audit trail summary metadata. */
  auditRecord?: {
    periodId: string;
    requester: string;
    approver?: string;
    reason: PeriodReopeningReason;
    reopenCountNext: number;
    timestamp: string;
  };
}

/** Error class thrown when assertPeriodReopening fails. */
export class PeriodReopeningRestrictionError extends Error {
  public readonly code: PeriodReopeningDenialCode;
  public readonly periodId: string;

  constructor(message: string, code: PeriodReopeningDenialCode, periodId: string) {
    super(message);
    this.name = "PeriodReopeningRestrictionError";
    this.code = code;
    this.periodId = periodId;
  }
}

const DEFAULT_AUTH_ROLES = ["PAYROLL_ADMIN", "SUPER_ADMIN"];
const DEFAULT_APPROVER_ROLES = ["COMPLIANCE_OFFICER", "FINANCE_DIRECTOR", "SUPER_ADMIN"];
const DEFAULT_MAX_REOPENS = 2;
const DEFAULT_LOCKOUT_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const DEFAULT_MIN_JUSTIFICATION_LEN = 15;

/**
 * Validates whether a closed, finalized, or draft payroll period can be safely reopened
 * in strict accordance with compliance and internal accounting restrictions.
 */
export function validatePeriodReopening(
  request: PeriodReopeningRequest,
  period: PayrollPeriodRecord | null | undefined,
  options: PeriodReopeningPolicyOptions = {},
  nowMs: number = Date.now()
): PeriodReopeningValidationResult {
  if (!request || !request.periodId || !request.requester || !request.requesterRole) {
    return {
      allowed: false,
      periodId: request?.periodId ?? "unknown",
      denialCode: "INVALID_REQUEST",
      reason:
        "Missing required fields in reopening request (periodId, requester, or requesterRole).",
      warnings: [],
    };
  }

  if (!period) {
    return {
      allowed: false,
      periodId: request.periodId,
      denialCode: "PERIOD_NOT_FOUND",
      reason: `Payroll period record "${request.periodId}" was not found.`,
      warnings: [],
    };
  }

  const warnings: string[] = [];
  const evalTime = request.requestedAtMs ?? nowMs;
  const authorizedRoles = (options.authorizedRoles ?? DEFAULT_AUTH_ROLES).map((r) =>
    r.toUpperCase()
  );
  const authorizedApproverRoles = (options.authorizedApproverRoles ?? DEFAULT_APPROVER_ROLES).map(
    (r) => r.toUpperCase()
  );
  const requireDualControl = options.requireDualControl ?? true;
  const maxReopens = period.maxAllowedReopens ?? options.maxReopenCount ?? DEFAULT_MAX_REOPENS;
  const lockoutWindowMs = period.lockoutWindowMs ?? options.lockoutWindowMs ?? DEFAULT_LOCKOUT_MS;
  const minJustificationLen = options.minJustificationLength ?? DEFAULT_MIN_JUSTIFICATION_LEN;

  // 1. Check current period lifecycle state
  if (period.state === "open" || period.state === "reopened") {
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "PERIOD_ALREADY_ACTIVE",
      reason: `Period "${period.periodId}" is already active in "${period.state}" state.`,
      warnings,
    };
  }

  // 2. Check for immutable audited lock
  if (period.state === "audited") {
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "PERIOD_IMMUTABLE_AUDITED",
      reason: `Period "${period.periodId}" has been formally audited and sealed; reopening is permanently prohibited.`,
      warnings,
    };
  }

  // 3. Check reopen counter against threshold
  if (period.reopenCount >= maxReopens) {
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "MAX_REOPENS_EXCEEDED",
      reason: `Period "${period.periodId}" has already reached the maximum allowed reopening limit (${period.reopenCount}/${maxReopens}).`,
      warnings,
    };
  }

  // 4. Check lockout duration elapsed since closure
  if (period.closedAtMs && evalTime - period.closedAtMs > lockoutWindowMs) {
    const elapsedDays = Math.floor((evalTime - period.closedAtMs) / (24 * 60 * 60 * 1000));
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "LOCKOUT_WINDOW_EXPIRED",
      reason: `Reopening window expired for period "${period.periodId}" (${elapsedDays} days elapsed since closure; limit is ${Math.floor(
        lockoutWindowMs / (24 * 60 * 60 * 1000)
      )} days).`,
      warnings,
    };
  }

  // 5. Verify requester role authorization
  if (!authorizedRoles.includes(request.requesterRole.trim().toUpperCase())) {
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "UNAUTHORIZED_REQUESTER_ROLE",
      reason: `Role "${request.requesterRole}" is not authorized to initiate reopening on period "${period.periodId}".`,
      warnings,
    };
  }

  // 6. Verify valid business reason
  if (!request.reason || !PERMITTED_REOPENING_REASONS.includes(request.reason)) {
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "INVALID_REASON",
      reason: `Reason "${String(request.reason)}" is not a recognized permitted reopening reason.`,
      warnings,
    };
  }

  // 7. Verify justification length and content
  if (!request.justification || request.justification.trim().length < minJustificationLen) {
    return {
      allowed: false,
      periodId: period.periodId,
      denialCode: "INSUFFICIENT_JUSTIFICATION",
      reason: `Reopening justification must be at least ${minJustificationLen} characters long.`,
      warnings,
    };
  }

  // 8. Dual control enforcement
  if (requireDualControl) {
    if (!request.approver) {
      return {
        allowed: false,
        periodId: period.periodId,
        denialCode: "DUAL_CONTROL_REQUIRED",
        reason: `Reopening period "${period.periodId}" requires dual-control approval from a designated compliance/finance officer.`,
        warnings,
      };
    }

    if (request.approver.trim().toLowerCase() === request.requester.trim().toLowerCase()) {
      return {
        allowed: false,
        periodId: period.periodId,
        denialCode: "SELF_APPROVAL_DISALLOWED",
        reason:
          "Self-approval is prohibited under dual-control policy: requester and approver must be distinct identities.",
        warnings,
      };
    }

    if (
      request.approverRole &&
      !authorizedApproverRoles.includes(request.approverRole.trim().toUpperCase())
    ) {
      return {
        allowed: false,
        periodId: period.periodId,
        denialCode: "UNAUTHORIZED_APPROVER_ROLE",
        reason: `Approver role "${request.approverRole}" is not in the list of authorized dual-control approver roles.`,
        warnings,
      };
    }
  }

  if (period.reopenCount > 0) {
    warnings.push(
      `This is reopening attempt #${period.reopenCount + 1} for period ${period.periodId}.`
    );
  }

  return {
    allowed: true,
    periodId: period.periodId,
    reason: `Period "${period.periodId}" approved for reopening under reason: ${request.reason}.`,
    warnings,
    auditRecord: {
      periodId: period.periodId,
      requester: request.requester,
      approver: request.approver,
      reason: request.reason,
      reopenCountNext: period.reopenCount + 1,
      timestamp: new Date(evalTime).toISOString(),
    },
  };
}

/**
 * Asserts that a period reopening request is allowed, throwing PeriodReopeningRestrictionError if not.
 */
export function assertPeriodReopeningAllowed(
  request: PeriodReopeningRequest,
  period: PayrollPeriodRecord | null | undefined,
  options?: PeriodReopeningPolicyOptions,
  nowMs?: number
): PeriodReopeningValidationResult {
  const result = validatePeriodReopening(request, period, options, nowMs);
  if (!result.allowed) {
    throw new PeriodReopeningRestrictionError(
      result.reason,
      result.denialCode ?? "INVALID_REQUEST",
      result.periodId
    );
  }
  return result;
}
