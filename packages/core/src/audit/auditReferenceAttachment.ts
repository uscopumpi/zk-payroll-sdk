/**
 * Audit Reference Attachment Helper
"
 * Attaches external audit reference metadata (document URLs, hash digests,
 * labels) to payroll operations for compliance trail purposes.
 *
 * ## Privacy & Security Guarantees
 * - Reference URIs and digests are validated but never echoed in user-facing error messages.
 * - Redacted messages are safe for dashboards, telemetry, and external logs.
 *
 * ## Retention Safeguards
 * - Attachments carry an explicit retention window so compliance tooling can
 *   prune or seal audit records before they expire.
 * - Retention windows are bounded to sane minimum/maximum limits to prevent
 *   accidental or malicious indefinite retention.
 * - Expired attachments can be detected and pruned without losing the audit trail.
 */

/** Supported attachment types */
export type AuditReferenceType = "document" | "receipt" | "proof" | "report" | "external";

/** Retention policy for an attachment */
export interface AuditReferenceRetentionPolicy {
  /** Number of days the attachment must be retained */
  retentionDays: number;
  /** Whether the attachment may be pruned automatically once expired */
  allowAutoPrune?: boolean;
  /** Optional legal hold reference that prevents pruning */
  legalHoldId?: string;
}

/** Input for attaching an audit reference to a payroll operation */
export interface AuditReferenceAttachmentInput {
  /** Unique payroll run or operation identifier */
  operationId: string;
  /** Type of reference being attached */
  referenceType: AuditReferenceType;
  /** Label or short description of the reference */
  label: string;
  /** URI or URL pointing to the reference document */
  uri?: string;
  /** SHA-256 hex digest of the referenced document for integrity verification */
  digest?: string;
  /** ISO 8601 timestamp when the reference was created or issued */
  issuedAt?: string;
  /** Optional non-sensitive metadata */
  metadata?: Record<string, unknown>;
  /** Retention policy applied to this attachment */
  retentionPolicy?: AuditReferenceRetentionPolicy;
}

/** Validation error codes */
export type AuditReferenceAttachmentErrorCode =
  | "MISSING_OPERATION_ID"
  | "MISSING_LABEL"
  | "INVALID_REFERENCE_TYPE"
  | "INVALID_URI_FORMAT"
  | "INVALID_DIGEST_FORMAT"
  | "INVALID_ISSUED_AT"
  | "LABEL_TOO_LONG"
  | "INVALID_RETENTION_POLICY"
  | "RETENTION_WINDOW_TOO_SHORT"
  | "RETENTION_WINDOW_TOO_LONG"
  | "RETENTION_HOLD_CONFLICT";

/** Structured validation error */
export interface AuditReferenceAttachmentError {
  code: AuditReferenceAttachmentErrorCode;
  field: string;
  message: string;
  redactedMessage: string;
}

/** Validation result */
export interface AuditReferenceAttachmentValidationResult {
  isValid: boolean;
  errors: AuditReferenceAttachmentError[];
}

/** Successful attachment result */
export interface AuditReferenceAttachment {
  operationId: string;
  referenceType: AuditReferenceType;
  label: string;
  uri?: string;
  digest?: string;
  issuedAt?: string;
  metadata?: Record<string, unknown>;
  attachedAt: number;
  redactedOperationId: string;
  /** Retention policy effectively applied to this attachment */
  retentionPolicy: ResolvedAuditRetentionPolicy;
  /** Timestamp (ms) when this attachment becomes eligible for pruning */
  expiresAt: number;
  /** Whether this attachment is currently expired */
  isExpired: boolean;
}

/** Resolved retention policy with defaults applied */
export interface ResolvedAuditRetentionPolicy {
  retentionDays: number;
  allowAutoPrune: boolean;
  legalHoldId?: string;
  /** Whether a legal hold is active and prevents pruning */
  legalHoldActive: boolean;
}

// Constants
const VALID_REFERENCE_TYPES: ReadonlySet<string> = new Set([
  "document",
  "receipt",
  "proof",
  "report",
  "external",
]);
const MAX_LABEL_LENGTH = 256;
const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/i;
const URI_REGEX = /^https?:\/\/.+/;

/** Default retention window in days (7 years) */
export const DEFAULT_AUDIT_RETENTION_DAYS = 365 * 7;
/** Minimum retention window in days (1 day) */
export const MIN_AUDIT_RETENTION_DAYS = 1;
/** Maximum retention window in days (100 years) */
export const MAX_AUDIT_RETENTION_DAYS = 36500;
/** Maximum length of a legal hold identifier */
export const MAX_LEGAL_HOLD_ID_LENGTH = 128;

const DAY_IN_MS = 24 * 60 * 60 * 1000;

// Redact helper
export function redactOperationId(id?: string): string {
  if (!id || id.trim().length === 0) return "[ANONYMOUS_OPERATION]";
  const clean = id.trim();
  if (clean.length <= 6) return "[REDACTED_OPERATION]";
  return `${clean.slice(0, 3)}***${clean.slice(-3)}`;
}

/** Resolve a retention policy, applying defaults and normalizing values. */
export function resolveAuditReferenceRetentionPolicy(
  policy?: AuditReferenceRetentionPolicy
): ResolvedAuditRetentionPolicy {
  const retentionDays = policy?.retentionDays ?? DEFAULT_AUDIT_RETENTION_DAYS;
  const allowAutoPrune = policy?.allowAutoPrune ?? true;
  const legalHoldId = policy?.legalHoldId;
  return {
    retentionDays,
    allowAutoPrune,
    legalHoldId,
    legalHoldActive: typeof legalHoldId === "string" && legalHoldId.trim().length > 0,
  };
}

/** Compute the expiration timestamp (in ms) for an attachment. */
export function computeAuditReferenceExpiresAt(
  attachedAt: number,
  policy: ResolvedAuditRetentionPolicy
): number {
  return attachedAt + policy.retentionDays * DAY_IN_MS;
}

/** Determine whether an attachment has expired at a given time. */
export function isAuditReferenceExpired(
  attachment: Pick<AuditReferenceAttachment, "expiresAt" | "retentionPolicy">,
  now: number = Date.now()
): boolean {
  if (attachment.retentionPolicy.legalHoldActive) return false;
  return now >= attachment.expiresAt;
}

/** Determine whether an attachment may be pruned at a given time. */
export function canPruneAuditReference(
  attachment: Pick<AuditReferenceAttachment, "expiresAt" | "retentionPolicy">,
  now: number = Date.now()
): boolean {
  if (!attachment.retentionPolicy.allowAutoPrune) return false;
  if (attachment.retentionPolicy.legalHoldActive) return false;
  return now >= attachment.expiresAt;
}

/** Filter attachments that are eligible for pruning. */
export function selectRetainedAuditReferences(
  attachments: ReadonlyArray<AuditReferenceAttachment>,
  now: number = Date.now()
): AuditReferenceAttachment[] {
  return attachments.filter((a) => !canPruneAuditReference(a, now));
}

/** Filter attachments that are eligible for pruning. */
export function selectPrunableAuditReferences(
  attachments: ReadonlyArray<AuditReferenceAttachment>,
  now: number = Date.now()
): AuditReferenceAttachment[] {
  return attachments.filter((a) => canPruneAuditReference(a, now));
}

// Validate function
export function validateAuditReferenceAttachment(
  input: AuditReferenceAttachmentInput
): AuditReferenceAttachmentValidationResult {
  const errors: AuditReferenceAttachmentError[] = [];

  if (!input.operationId || input.operationId.trim().length === 0) {
    errors.push({
      code: "MISSING_OPERATION_ID",
      field: "operationId",
      message: "Operation ID is required.",
      redactedMessage: "Operation ID is required.",
    });
  }

  if (!input.label || input.label.trim().length === 0) {
    errors.push({
      code: "MISSING_LABEL",
      field: "label",
      message: "A descriptive label is required for the audit reference.",
      redactedMessage: "A descriptive label is required for the audit reference.",
    });
  } else if (input.label.length > MAX_LABEL_LENGTH) {
    errors.push({
      code: "LABEL_TOO_LONG",
      field: "label",
      message: `Label exceeds maximum length of ${MAX_LABEL_LENGTH} characters.`,
      redactedMessage: `Label exceeds maximum length of ${MAX_LABEL_LENGTH} characters.`,
    });
  }

  if (!VALID_REFERENCE_TYPES.has(input.referenceType)) {
    errors.push({
      code: "INVALID_REFERENCE_TYPE",
      field: "referenceType",
      message: `Invalid reference type "${input.referenceType}". Expected one of: $z[...VALID_REFERENCE_TYPES].join(", ")}.`,
      redactedMessage: "Invalid reference type provided.",
    });
  }

  if (input.uri !== undefined && input.uri !== null) {
    if (typeof input.uri !== "string" || !URI_REGEX.test(input.uri.trim())) {
      errors.push({
        code: "INVALID_URI_FORMAT",
        field: "uri",
        message: "URI must be a valid HTTP or HTTPS URL.",
        redactedMessage: "URI must be a valid HTTP or HTTPS URL.",
      });
    }
  }

  if (input.digest !== undefined && input.digest !== null) {
    if (typeof input.digest !== "string" || !SHA256_HEX_REGEX.test(input.digest.trim())) {
      errors.push({
        code: "INVALID_DIGEST_FORMAT",
        field: "digest",
        message: "Digest must be a 64-character lowercase hex SHA-256 hash.",
        redactedMessage: "Digest format is invalid.",
      });
    }
  }

  if (input.issuedAt !== undefined && input.issuedAt !== null) {
    const parsed = Date.parse(input.issuedAt);
    if (isNaN(parsed)) {
      errors.push({
        code: "INVALID_ISSUED_AT",
        field: "issuedAt",
        message: "issuedAt must be a valid ISO 8601 date string.",
        redactedMessage: "issuedAt must be a valid ISO 8601 date string.",
      });
    }
  }

  if (input.retentionPolicy !== undefined && input.retentionPolicy !== null) {
    const policy = input.retentionPolicy;
    if (typeof policy !== "object" || Array.isArray(policy)) {
      errors.push({
        code: "INVALID_RETENTION_POLICY",
        field: "retentionPolicy",
        message: "Retention policy must be an object.",
        redactedMessage: "Retention policy is invalid.",
      });
    } else {
      const retentionDays = policy.retentionDays;
      if (retentionDays !== undefined) {
        if (
          typeof retentionDays !== "number" ||
          !Number.isFinite(retentionDays) ||
          !Number.isInteger(retentionDays)
        ) {
          errors.push({
            code: "INVALID_RETENTION_POLICY",
            field: "retentionPolicy.retentionDays",
            message: "Retention days must be a finite integer.",
            redactedMessage: "Retention policy is invalid.",
          });
        } else if (retentionDays < MIN_AUDIT_RETENTION_DAYS) {
          errors.push({
            code: "RETENTION_WINDOW_TOO_SHORT",
            field: "retentionPolicy.retentionDays",
            message: `Retention window must be at least ${MIN_AUDIT_RETENTION_DAYS} day(s).`,
            redactedMessage: `Retention window must be at least ${MIN_AUDIT_RETENTION_DAYS} day(s).`,
          });
        } else if (retentionDays > MAX_AUDIT_RETENTION_DAYS) {
          errors.push({
            code: "RETENTION_WINDOW_TOO_LONG",
            field: "retentionPolicy.retentionDays",
            message: `Retention window must not exceed ${MAX_AUDIT_RETENTION_DAYS} days.`,
            redactedMessage: `Retention window must not exceed ${MAX_AUDIT_RETENTION_DAYS} days.`,
          });
        }
      }

      if (policy.allowAutoPrune !== undefined && typeof policy.allowAutoPrune !== "boolean") {
        errors.push({
          code: "INVALID_RETENTION_POLICY",
          field: "retentionPolicy.allowAutoPrune",
          message: "allowAutoPrune must be a boolean.",
          redactedMessage: "Retention policy is invalid.",
        });
      }

      if (policy.legalHoldId !== undefined && policy.legalHoldId !== null) {
        if (typeof policy.legalHoldId !== "string") {
          errors.push({
            code: "INVALID_RETENTION_POLICY",
            field: "retentionPolicy.legalHoldId",
            message: "legalHoldId must be a string.",
            redactedMessage: "Retention policy is invalid.",
          });
        } else if (policy.legalHoldId.trim().length > MAX_LEGAL_HOLD_ID_LENGTH) {
          errors.push({
            code: "INVALID_RETENTION_POLICY",
            field: "retentionPolicy.legalHoldId",
            message: `Legal hold ID must not exceed ${MAX_LEGAL_HOLD_ID_LENGTH} characters.`,
            redactedMessage: "Retention policy is invalid.",
          });
        }
      }
    }
  }

  return { isValid: errors.length === 0, errors };
}

// Main helper
export function attachAuditReference(
  input: AuditReferenceAttachmentInput
): AuditReferenceAttachment {
  const validation = validateAuditReferenceAttachment(input);
  if (!validation.isValid) {
    const redactedMessages = validation.errors.map((e) => e.redactedMessage).join("; ");
    throw new AuditReferenceAttachmentValidationError(validation.errors, redactedMessages);
  }

  const attachedAt = Date.now();
  const retentionPolicy = resolveAuditReferenceRetentionPolicy(input.retentionPolicy);
  const expiresAt = computeAuditReferenceExpiresAt(attachedAt, retentionPolicy);

  return {
    operationId: input.operationId.trim(),
    referenceType: input.referenceType,
    label: input.label.trim(),
    uri: input.uri?.trim(),
    digest: input.digest?.trim().toLowerCase(),
    issuedAt: input.issuedAt,
    metadata: input.metadata,
    attachedAt,
    redactedOperationId: redactOperationId(input.operationId),
    retentionPolicy,
    expiresAt,
    isExpired: isAuditReferenceExpired({ expiresAt, retentionPolicy }, attachedAt),
  };
}

/** Return a sanitized copy of an attachment suitable for telemetry or external logs. */
export function redactAuditReferenceAttachment(
  attachment: AuditReferenceAttachment
): Record<string, unknown> {
  return {
    operationId: attachment.redactedOperationId,
    referenceType: attachment.referenceType,
    label: attachment.label,
    hasUri: Boolean(attachment.uri),
    hasDigest: Boolean(attachment.digest),
    issuedAt: attachment.issuedAt,
    attachedAt: attachment.attachedAt,
    expiresAt: attachment.expiresAt,
    isExpired: attachment.isExpired,
    retentionDays: attachment.retentionPolicy.retentionDays,
    allowAutoPrune: attachment.retentionPolicy.allowAutoPrune,
    legalHoldActive: attachment.retentionPolicy.legalHoldActive,
  };
}

// Error class
export class AuditReferenceAttachmentValidationError extends Error {
  readonly code = "AUDIT_REFERENCE_VALIDATION_FAILED";
  readonly validationErrors: AuditReferenceAttachmentError[];

  constructor(errors: AuditReferenceAttachmentError[], redactedMessage: string) {
    super(redactedMessage);
    this.name = "AuditReferenceAttachmentValidationError";
    this.validationErrors = errors;
  }
}
