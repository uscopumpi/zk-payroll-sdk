/**
 * Payroll Responsibility Delegation Audit
 *
 * Implements SDK-level audit evaluation and validation for delegated payroll
 * operational responsibilities (Issue #708).
 *
 * Ensures that whenever a delegate attempts to execute a payroll action
 * (e.g., batch submission, salary adjustments, approval, reconciliation),
 * an active, unrevoked, unexpired delegation grant exists with sufficient scope.
 *
 * @module
 */

/**
 * Standard operational responsibilities that can be delegated within ZK Payroll.
 */
export type DelegatedPayrollResponsibility =
  | "BATCH_SUBMISSION"
  | "PAYMENT_AUTHORIZATION"
  | "SALARY_UPDATE"
  | "AUDIT_EXPORT"
  | "RECONCILIATION"
  | "DISPUTE_RESOLUTION"
  | "EMERGENCY_ACTIONS";

export const ALL_DELEGATED_RESPONSIBILITIES: readonly DelegatedPayrollResponsibility[] = [
  "BATCH_SUBMISSION",
  "PAYMENT_AUTHORIZATION",
  "SALARY_UPDATE",
  "AUDIT_EXPORT",
  "RECONCILIATION",
  "DISPUTE_RESOLUTION",
  "EMERGENCY_ACTIONS",
];

/**
 * Stored or queried record of an issued responsibility delegation.
 */
export interface PayrollDelegationRecord {
  /** Unique identifier of the delegation grant. */
  delegationId: string;
  /** Address or identifier of the principal granting authority. */
  delegator: string;
  /** Address or identifier of the appointed operational delegate. */
  delegate: string;
  /** Set of responsibilities granted to the delegate. */
  responsibilities: DelegatedPayrollResponsibility[];
  /** Timestamp when the delegation becomes active (epoch ms). */
  validFromMs: number;
  /** Timestamp when the delegation expires (epoch ms). */
  validToMs: number;
  /** Whether the delegation has been revoked prematurely. */
  revoked?: boolean;
  /** Optional timestamp when revocation took place (epoch ms). */
  revokedAtMs?: number;
  /** Optional reason for revocation. */
  revocationReason?: string;
  /** Optional custom metadata. */
  metadata?: Record<string, unknown>;
}

/**
 * Request to audit whether a delegate holds authority for a specific responsibility.
 */
export interface PayrollDelegationAuditRequest {
  /** Identifier of the delegation grant being evaluated. */
  delegationId: string;
  /** The specific operational action or responsibility claimed by the caller. */
  claimedResponsibility: DelegatedPayrollResponsibility;
  /** Address of the executing actor claiming delegated authority. */
  delegate: string;
  /** Optional evaluation timestamp (defaults to current time). */
  timestampMs?: number;
}

/** Reason codes when delegation audit fails. */
export type DelegationAuditDenialCode =
  | "NO_ACTIVE_DELEGATION"
  | "DELEGATION_REVOKED"
  | "DELEGATION_EXPIRED"
  | "DELEGATION_NOT_YET_ACTIVE"
  | "UNAUTHORIZED_RESPONSIBILITY"
  | "DELEGATE_MISMATCH"
  | "INVALID_REQUEST";

/**
 * Outcome of a responsibility delegation audit evaluation.
 */
export interface PayrollDelegationAuditDecision {
  /** True when the delegate is fully authorized to perform the claimed action. */
  authorized: boolean;
  /** The delegation identifier evaluated. */
  delegationId: string;
  /** Denial code present when authorized is false. */
  denialCode?: DelegationAuditDenialCode;
  /** Privacy-preserving, actionable explanatory message. */
  reason: string;
  /** Audit snapshot of the delegation record. */
  delegation?: PayrollDelegationRecord;
}

/** Error class thrown on delegation validation failures. */
export class PayrollDelegationAuditError extends Error {
  public readonly code: DelegationAuditDenialCode;
  public readonly delegationId: string;

  constructor(message: string, code: DelegationAuditDenialCode, delegationId: string) {
    super(message);
    this.name = "PayrollDelegationAuditError";
    this.code = code;
    this.delegationId = delegationId;
  }
}

/**
 * Helper to mask sensitive delegate and delegator public keys for privacy-safe logs.
 */
export function maskAddress(address?: string): string {
  if (!address || typeof address !== "string") return "[UNKNOWN]";
  const trimmed = address.trim();
  if (trimmed.length <= 10) return trimmed;
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-4)}`;
}

/**
 * Validates the structural integrity and timebounds of a delegation record.
 */
export function validatePayrollDelegationRecord(record: PayrollDelegationRecord): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (!record || typeof record !== "object") {
    return { valid: false, errors: ["Delegation record must be a defined object."] };
  }

  if (
    !record.delegationId ||
    typeof record.delegationId !== "string" ||
    !record.delegationId.trim()
  ) {
    errors.push("Missing or invalid delegationId.");
  }

  if (!record.delegator || typeof record.delegator !== "string" || !record.delegator.trim()) {
    errors.push("Missing or invalid delegator address.");
  }

  if (!record.delegate || typeof record.delegate !== "string" || !record.delegate.trim()) {
    errors.push("Missing or invalid delegate address.");
  }

  if (record.delegator && record.delegate && record.delegator.trim() === record.delegate.trim()) {
    errors.push("Delegator and delegate cannot be the same address.");
  }

  if (!Array.isArray(record.responsibilities) || record.responsibilities.length === 0) {
    errors.push("Responsibilities list must contain at least one valid responsibility.");
  } else {
    for (const resp of record.responsibilities) {
      if (!ALL_DELEGATED_RESPONSIBILITIES.includes(resp)) {
        errors.push(`Unrecognized delegated responsibility: ${resp}`);
      }
    }
  }

  if (
    typeof record.validFromMs !== "number" ||
    isNaN(record.validFromMs) ||
    record.validFromMs < 0
  ) {
    errors.push("validFromMs must be a non-negative timestamp.");
  }

  if (typeof record.validToMs !== "number" || isNaN(record.validToMs) || record.validToMs <= 0) {
    errors.push("validToMs must be a positive timestamp.");
  }

  if (record.validFromMs >= record.validToMs) {
    errors.push("validFromMs must precede validToMs.");
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Audits a delegation grant against a claimed responsibility and executing actor.
 */
export function auditPayrollResponsibilityDelegation(
  request: PayrollDelegationAuditRequest,
  delegation: PayrollDelegationRecord | null | undefined,
  evaluationTimeMs: number = Date.now()
): PayrollDelegationAuditDecision {
  if (!request || !request.delegationId || !request.claimedResponsibility || !request.delegate) {
    return {
      authorized: false,
      delegationId: request?.delegationId ?? "unknown",
      denialCode: "INVALID_REQUEST",
      reason:
        "Audit request is missing required fields (delegationId, claimedResponsibility, or delegate).",
    };
  }

  if (!delegation) {
    return {
      authorized: false,
      delegationId: request.delegationId,
      denialCode: "NO_ACTIVE_DELEGATION",
      reason: `No delegation record found for delegation ID: ${request.delegationId}`,
    };
  }

  if (delegation.delegationId !== request.delegationId) {
    return {
      authorized: false,
      delegationId: request.delegationId,
      denialCode: "NO_ACTIVE_DELEGATION",
      reason: `Delegation ID mismatch: record (${delegation.delegationId}) does not match request (${request.delegationId}).`,
      delegation,
    };
  }

  const now = request.timestampMs ?? evaluationTimeMs;

  // 1. Verify delegate identity matches
  if (delegation.delegate.trim().toLowerCase() !== request.delegate.trim().toLowerCase()) {
    return {
      authorized: false,
      delegationId: delegation.delegationId,
      denialCode: "DELEGATE_MISMATCH",
      reason: `Actor ${maskAddress(request.delegate)} is not the authorized delegate for grant ${delegation.delegationId}.`,
      delegation,
    };
  }

  // 2. Check revocation status
  if (delegation.revoked || (delegation.revokedAtMs && delegation.revokedAtMs <= now)) {
    return {
      authorized: false,
      delegationId: delegation.delegationId,
      denialCode: "DELEGATION_REVOKED",
      reason: `Delegation grant ${delegation.delegationId} was revoked${
        delegation.revocationReason ? `: ${delegation.revocationReason}` : "."
      }`,
      delegation,
    };
  }

  // 3. Check start timebounds
  if (now < delegation.validFromMs) {
    return {
      authorized: false,
      delegationId: delegation.delegationId,
      denialCode: "DELEGATION_NOT_YET_ACTIVE",
      reason: `Delegation grant ${delegation.delegationId} does not become active until ${new Date(
        delegation.validFromMs
      ).toISOString()}.`,
      delegation,
    };
  }

  // 4. Check expiration
  if (now > delegation.validToMs) {
    return {
      authorized: false,
      delegationId: delegation.delegationId,
      denialCode: "DELEGATION_EXPIRED",
      reason: `Delegation grant ${delegation.delegationId} expired at ${new Date(
        delegation.validToMs
      ).toISOString()}.`,
      delegation,
    };
  }

  // 5. Check responsibility authorization
  if (!delegation.responsibilities.includes(request.claimedResponsibility)) {
    return {
      authorized: false,
      delegationId: delegation.delegationId,
      denialCode: "UNAUTHORIZED_RESPONSIBILITY",
      reason: `Delegation grant ${delegation.delegationId} does not include responsibility "${request.claimedResponsibility}".`,
      delegation,
    };
  }

  return {
    authorized: true,
    delegationId: delegation.delegationId,
    reason: `Actor ${maskAddress(request.delegate)} is authorized for "${request.claimedResponsibility}" via grant ${delegation.delegationId}.`,
    delegation,
  };
}

/**
 * Asserts that a delegation is authorized, throwing PayrollDelegationAuditError if not.
 */
export function assertPayrollResponsibilityDelegation(
  request: PayrollDelegationAuditRequest,
  delegation: PayrollDelegationRecord | null | undefined,
  evaluationTimeMs: number = Date.now()
): PayrollDelegationAuditDecision {
  const decision = auditPayrollResponsibilityDelegation(request, delegation, evaluationTimeMs);
  if (!decision.authorized) {
    throw new PayrollDelegationAuditError(
      decision.reason,
      decision.denialCode ?? "NO_ACTIVE_DELEGATION",
      decision.delegationId
    );
  }
  return decision;
}
