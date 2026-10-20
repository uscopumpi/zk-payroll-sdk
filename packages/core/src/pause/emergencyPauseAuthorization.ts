/**
 * Emergency Payroll Pause Authorization
 *
 * Implements SDK-layer validation and authorization checks for emergency payroll
 * pause execution (Issue #692).
 *
 * Ensures that emergency operations halt (global or targeted) can only be triggered
 * by accredited security responders, enforces dual/multisig co-signing for critical
 * global pauses, validates mandatory incident tracking metadata, and outputs structured
 * audit records.
 *
 * @module
 */

/**
 * Functional subsystems that can be halted under emergency pause controls.
 */
export type EmergencyPauseScope =
  "ALL" | "PAYROLL_ONLY" | "DISBURSEMENTS_ONLY" | "DEPOSITS_ONLY" | "PROOF_VERIFICATION_ONLY";

export const ALL_EMERGENCY_PAUSE_SCOPES: readonly EmergencyPauseScope[] = [
  "ALL",
  "PAYROLL_ONLY",
  "DISBURSEMENTS_ONLY",
  "DEPOSITS_ONLY",
  "PROOF_VERIFICATION_ONLY",
];

/**
 * Threat classification severity levels.
 */
export type EmergencySeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM";

/**
 * Request initiating an emergency payroll pause.
 */
export interface EmergencyPauseRequest {
  /** Public key / address of the security responder initiating the pause. */
  requester: string;
  /** Role held by the initiator (e.g. "SECURITY_ADMIN", "EMERGENCY_RESPONDER"). */
  requesterRole: string;
  /** Extent of system operations to pause. */
  scope: EmergencyPauseScope;
  /** Assessed severity of the active threat. */
  severity: EmergencySeverityLevel;
  /** Mandatory tracking identifier (e.g. "INC-2026-888" or "SEC-TICKET-01"). */
  incidentTicket: string;
  /** Explicit justification explaining the active incident. */
  reason: string;
  /** Optional addresses of co-authorizing responders (for multisig / dual-control). */
  coSigners?: string[];
  /** Optional roles of the co-signers. */
  coSignerRoles?: string[];
  /** Epoch timestamp of the request submission (defaults to now). */
  requestedAtMs?: number;
}

/**
 * Governance policy parameters controlling emergency pause approvals.
 */
export interface EmergencyPausePolicy {
  /** Roles authorized to initiate emergency pauses (default: ["SECURITY_ADMIN", "EMERGENCY_MULTISIG", "SUPER_ADMIN"]). */
  authorizedInitiatorRoles?: string[];
  /** Roles authorized to serve as co-signers (default: ["SECURITY_ADMIN", "COMPLIANCE_OFFICER", "FINANCE_DIRECTOR", "SUPER_ADMIN"]). */
  authorizedCoSignerRoles?: string[];
  /** Whether a co-signer is mandatory for global "ALL" scope or "CRITICAL" severity (default: true). */
  requireCoSignerForCriticalOrGlobal?: boolean;
  /** Minimum number of distinct co-signers required when co-signing is enforced (default: 1). */
  minCoSigners?: number;
  /** Minimum character length required for the reason string (default: 15). */
  minReasonLength?: number;
  /** Minimum character length required for incident ticket identifier (default: 6). */
  minTicketLength?: number;
}

/** Specific denial reason codes for rejected emergency pauses. */
export type EmergencyPauseDenialCode =
  | "UNAUTHORIZED_INITIATOR"
  | "UNAUTHORIZED_CO_SIGNER"
  | "INSUFFICIENT_CO_SIGNERS"
  | "SELF_CO_SIGN_PROHIBITED"
  | "DUPLICATE_CO_SIGNERS"
  | "INVALID_INCIDENT_TICKET"
  | "INSUFFICIENT_JUSTIFICATION"
  | "INVALID_SCOPE"
  | "INVALID_REQUEST";

/**
 * Authorization decision outcome for an emergency pause request.
 */
export interface EmergencyPauseDecision {
  /** True when the emergency pause is formally validated and authorized to execute. */
  authorized: boolean;
  /** Scope of operations targeted by the pause. */
  scope: EmergencyPauseScope;
  /** Assessed severity. */
  severity: EmergencySeverityLevel;
  /** Denial code present when authorized is false. */
  denialCode?: EmergencyPauseDenialCode;
  /** Privacy-safe human-readable rationale. */
  reason: string;
  /** Advisory warnings. */
  warnings: string[];
  /** Structured audit trail artifact ready for telemetry and governance logging. */
  auditPayload?: {
    requester: string;
    requesterRole: string;
    scope: EmergencyPauseScope;
    severity: EmergencySeverityLevel;
    incidentTicket: string;
    coSigners: string[];
    timestamp: string;
  };
}

/** Error class thrown by assertEmergencyPayrollPauseAuthorized. */
export class EmergencyPauseAuthorizationError extends Error {
  public readonly code: EmergencyPauseDenialCode;
  public readonly scope: EmergencyPauseScope;

  constructor(message: string, code: EmergencyPauseDenialCode, scope: EmergencyPauseScope) {
    super(message);
    this.name = "EmergencyPauseAuthorizationError";
    this.code = code;
    this.scope = scope;
  }
}

const DEFAULT_INITIATOR_ROLES = ["SECURITY_ADMIN", "EMERGENCY_MULTISIG", "SUPER_ADMIN"];
const DEFAULT_CO_SIGNER_ROLES = [
  "SECURITY_ADMIN",
  "COMPLIANCE_OFFICER",
  "FINANCE_DIRECTOR",
  "SUPER_ADMIN",
];
const DEFAULT_MIN_REASON_LEN = 15;
const DEFAULT_MIN_TICKET_LEN = 6;

/**
 * Evaluates and authorizes an emergency payroll pause request against organizational policies.
 */
export function authorizeEmergencyPayrollPause(
  request: EmergencyPauseRequest,
  policy: EmergencyPausePolicy = {},
  nowMs: number = Date.now()
): EmergencyPauseDecision {
  if (!request || !request.requester || !request.requesterRole || !request.scope) {
    return {
      authorized: false,
      scope: request?.scope ?? "ALL",
      severity: request?.severity ?? "HIGH",
      denialCode: "INVALID_REQUEST",
      reason:
        "Missing required fields in emergency pause request (requester, requesterRole, or scope).",
      warnings: [],
    };
  }

  const warnings: string[] = [];
  const evalTime = request.requestedAtMs ?? nowMs;
  const initiatorRoles = (policy.authorizedInitiatorRoles ?? DEFAULT_INITIATOR_ROLES).map((r) =>
    r.toUpperCase()
  );
  const coSignerRoles = (policy.authorizedCoSignerRoles ?? DEFAULT_CO_SIGNER_ROLES).map((r) =>
    r.toUpperCase()
  );
  const minReasonLen = policy.minReasonLength ?? DEFAULT_MIN_REASON_LEN;
  const minTicketLen = policy.minTicketLength ?? DEFAULT_MIN_TICKET_LEN;
  const requireCoSigner = policy.requireCoSignerForCriticalOrGlobal ?? true;
  const minCoSigners = policy.minCoSigners ?? 1;

  // 1. Validate Scope
  if (!ALL_EMERGENCY_PAUSE_SCOPES.includes(request.scope)) {
    return {
      authorized: false,
      scope: request.scope,
      severity: request.severity,
      denialCode: "INVALID_SCOPE",
      reason: `Unrecognized emergency pause scope: "${String(request.scope)}".`,
      warnings,
    };
  }

  // 2. Validate Incident Ticket Format
  if (!request.incidentTicket || request.incidentTicket.trim().length < minTicketLen) {
    return {
      authorized: false,
      scope: request.scope,
      severity: request.severity,
      denialCode: "INVALID_INCIDENT_TICKET",
      reason: `Emergency pause requires a valid incident tracking ticket of at least ${minTicketLen} characters.`,
      warnings,
    };
  }

  // 3. Validate Justification Length
  if (!request.reason || request.reason.trim().length < minReasonLen) {
    return {
      authorized: false,
      scope: request.scope,
      severity: request.severity,
      denialCode: "INSUFFICIENT_JUSTIFICATION",
      reason: `Emergency pause reason must be at least ${minReasonLen} characters describing the incident.`,
      warnings,
    };
  }

  // 4. Verify Initiator Role
  const role = request.requesterRole.trim().toUpperCase();
  if (!initiatorRoles.includes(role)) {
    return {
      authorized: false,
      scope: request.scope,
      severity: request.severity,
      denialCode: "UNAUTHORIZED_INITIATOR",
      reason: `Role "${request.requesterRole}" is not authorized to initiate emergency pauses. Required one of: ${initiatorRoles.join(
        ", "
      )}`,
      warnings,
    };
  }

  // 5. Check Co-signing Requirements for Global or Critical Severity
  const needsCoSigner =
    requireCoSigner && (request.scope === "ALL" || request.severity === "CRITICAL");
  const rawCoSigners = request.coSigners ?? [];

  if (needsCoSigner) {
    if (rawCoSigners.length < minCoSigners) {
      return {
        authorized: false,
        scope: request.scope,
        severity: request.severity,
        denialCode: "INSUFFICIENT_CO_SIGNERS",
        reason: `Emergency pause with scope "${request.scope}" or severity "${request.severity}" requires at least ${minCoSigners} authorized co-signer(s).`,
        warnings,
      };
    }

    // Verify no self-cosigning
    const requesterClean = request.requester.trim().toLowerCase();
    for (const cs of rawCoSigners) {
      if (cs.trim().toLowerCase() === requesterClean) {
        return {
          authorized: false,
          scope: request.scope,
          severity: request.severity,
          denialCode: "SELF_CO_SIGN_PROHIBITED",
          reason:
            "Requester cannot serve as their own co-signer for emergency pause authorization.",
          warnings,
        };
      }
    }

    // Verify distinct co-signers (no duplicates)
    const uniqueCoSigners = new Set(rawCoSigners.map((c) => c.trim().toLowerCase()));
    if (uniqueCoSigners.size !== rawCoSigners.length) {
      return {
        authorized: false,
        scope: request.scope,
        severity: request.severity,
        denialCode: "DUPLICATE_CO_SIGNERS",
        reason: "Co-signers list contains duplicate addresses.",
        warnings,
      };
    }

    // Verify co-signer roles if provided
    if (request.coSignerRoles && request.coSignerRoles.length > 0) {
      for (const csr of request.coSignerRoles) {
        if (!coSignerRoles.includes(csr.trim().toUpperCase())) {
          return {
            authorized: false,
            scope: request.scope,
            severity: request.severity,
            denialCode: "UNAUTHORIZED_CO_SIGNER",
            reason: `Co-signer role "${csr}" is not recognized among authorized co-signer roles.`,
            warnings,
          };
        }
      }
    }
  }

  if (request.severity === "CRITICAL") {
    warnings.push(
      "CRITICAL severity emergency pause will immediately halt contract operations upon submission."
    );
  }

  return {
    authorized: true,
    scope: request.scope,
    severity: request.severity,
    reason: `Emergency pause authorized for scope ${request.scope} under incident ${request.incidentTicket}.`,
    warnings,
    auditPayload: {
      requester: request.requester,
      requesterRole: request.requesterRole,
      scope: request.scope,
      severity: request.severity,
      incidentTicket: request.incidentTicket,
      coSigners: rawCoSigners,
      timestamp: new Date(evalTime).toISOString(),
    },
  };
}

/**
 * Asserts that an emergency payroll pause is authorized, throwing EmergencyPauseAuthorizationError if rejected.
 */
export function assertEmergencyPayrollPauseAuthorized(
  request: EmergencyPauseRequest,
  policy?: EmergencyPausePolicy,
  nowMs?: number
): EmergencyPauseDecision {
  const decision = authorizeEmergencyPayrollPause(request, policy, nowMs);
  if (!decision.authorized) {
    throw new EmergencyPauseAuthorizationError(
      decision.reason,
      decision.denialCode ?? "UNAUTHORIZED_INITIATOR",
      decision.scope
    );
  }
  return decision;
}
