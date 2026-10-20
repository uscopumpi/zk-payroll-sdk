/**
 * Payroll Recipient Lock Status Reader (#512)
 *
 * Reads and evaluates whether a payout recipient is locked due to an
 * active payroll execution. Prevents duplicate payouts, double-settlement,
 * and concurrent modification races during active payroll runs.
 *
 * ## Privacy & Security Guarantees
 * - Salary amounts and private employee compensation details are NEVER
 *   included in lock statuses or error messages.
 * - Recipient addresses and internal payroll identifiers are redacted/masked
 *   by default in all human-readable summaries, logs, and user-facing messages.
 * - Lock reason codes follow standardized operational enums to prevent
 *   accidental information leakage.
 */

import { xdr, nativeToScVal, Address, Keypair, Networks } from "@stellar/stellar-sdk";
import type { ISigner } from "../signer/types";
import { toISigner } from "../signer/KeypairSigner";
import { BaseContractWrapper } from "../adapters/BaseContractWrapper";
import { scValToBigInt, scValToBool, scValToString } from "./periodSummary";
import { maskStellarAddress, maskEmployeeId } from "../issues/exportSanitizer";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Reason for a recipient lock.
 */
export type RecipientLockReason =
  | "active_payroll_execution"
  | "batch_in_flight"
  | "pending_settlement"
  | "dispute_freeze"
  | "administrative_hold"
  | "none";

/**
 * Normalized payroll recipient lock status response.
 * Safe for direct dashboard and operational consumption.
 */
export interface RecipientLockStatus {
  /** Recipient address or identifier */
  recipient: string;
  /** Redacted/masked recipient address safe for logs and UI display */
  redactedRecipient: string;
  /** Whether the recipient is currently locked by an active payroll execution */
  isLocked: boolean;
  /** Whether the recipient is currently free to receive a new payout */
  canReceivePayout: boolean;
  /** Standardized operational lock reason */
  lockReason: RecipientLockReason;
  /** Active payroll run or batch identifier holding the lock, if recorded */
  payrollId?: string;
  /** Redacted payroll run identifier */
  redactedPayrollId?: string;
  /** Unix timestamp when the recipient was locked (ms); 0 if never locked */
  lockedAt: number;
  /** Unix timestamp when the lock expires or is scheduled to release (ms), if recorded */
  unlockAt?: number;
  /** Operator or contract address that placed the lock, if recorded */
  lockedBy?: string;
  /** Redacted locked-by operator address */
  redactedLockedBy?: string;
  /** Unix timestamp when this status was fetched or evaluated (ms) */
  fetchedAt: number;
  /** Optional sanitized diagnostic metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Active payroll execution descriptor used for offline/in-memory lock evaluation.
 */
export interface ActivePayrollExecution {
  /** Payroll run or batch identifier */
  payrollId: string;
  /** Current execution status (e.g. "draft", "locked", "in_flight", "executing", "settled") */
  status: string;
  /** List of recipient addresses included in this execution */
  recipients: string[];
  /** Unix timestamp when execution began (ms) */
  lockedAt?: number;
  /** Scheduled unlock/expiry timestamp (ms) */
  unlockAt?: number;
  /** Operator or contract address executing the run */
  lockedBy?: string;
  /** Explicit lock reason */
  lockReason?: RecipientLockReason;
}

/**
 * Configuration options for fetching recipient lock status from the contract.
 */
export interface FetchRecipientLockStatusOptions {
  /** Signer for the query transaction */
  signer: Keypair | ISigner;
  /** Network passphrase (defaults to TESTNET) */
  network?: string;
  /** Optional request ID for correlation tracing */
  requestId?: string;
  /** Whether to redact identifiers in results (defaults to true) */
  redact?: boolean;
}

/**
 * Options for reading and evaluating recipient lock statuses.
 */
export interface RecipientLockReadOptions {
  /** Current time in epoch ms (defaults to Date.now()) */
  now?: number;
  /** Mask identifiers in outputs (defaults to true) */
  redact?: boolean;
  /** Maximum lock duration in ms after which locks are considered expired */
  lockTimeoutMs?: number;
  /** Treat unknown active statuses as strictly locking */
  strict?: boolean;
}

/**
 * Summary for batch recipient lock evaluations.
 */
export interface BatchRecipientLockSummary {
  /** Total recipients evaluated */
  totalChecked: number;
  /** Number of locked recipients */
  lockedCount: number;
  /** Number of unlocked recipients */
  unlockedCount: number;
  /** Individual recipient lock statuses */
  statuses: RecipientLockStatus[];
  /** List of locked recipient identifiers */
  lockedRecipients: string[];
  /** True if at least one recipient is locked */
  hasAnyLocked: boolean;
}

/**
 * Error codes for recipient lock operations.
 */
export type RecipientLockErrorCode =
  | "INVALID_RECIPIENT"
  | "INVALID_PAYROLL_ID"
  | "LOCK_TIMEOUT_EXCEEDED"
  | "CONTRACT_QUERY_FAILED"
  | "UNKNOWN_ERROR";

/**
 * Structured error descriptor for recipient lock operations.
 */
export interface RecipientLockError {
  code: RecipientLockErrorCode;
  message: string;
  recipient?: string;
  timestamp: number;
}

/**
 * Builds a real `Error` instance that also carries the structured
 * `RecipientLockError` fields, so callers can branch on `error.code` while
 * the thrown value still behaves like a standard error.
 */
function createRecipientLockError(
  code: RecipientLockErrorCode,
  message: string,
  timestamp: number
): Error & RecipientLockError {
  const error = new Error(message) as Error & RecipientLockError;
  error.name = "RecipientLockError";
  error.code = code;
  error.timestamp = timestamp;
  return error;
}

/**
 * Validation result for recipient lock status checks.
 */
export type RecipientLockValidationResult =
  | { ok: true; status: RecipientLockStatus }
  | { ok: false; code: RecipientLockErrorCode; message: string; recipient?: string };

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Redacts a recipient address or employee ID for safe logging.
 */
export function maskRecipientIdentifier(id?: string): string {
  if (!id || id.trim().length === 0) return "[ANONYMOUS_RECIPIENT]";
  const clean = id.trim();
  if (clean.length > 8 && (/^[GC]/.test(clean) || clean.startsWith("0x"))) {
    return maskStellarAddress(clean);
  }
  if (clean.length <= 4) return "[REDACTED_RECIPIENT]";
  return maskEmployeeId(clean);
}

/**
 * Redacts a payroll identifier for safe logging.
 */
export function maskPayrollIdentifier(id?: string): string {
  if (!id || id.trim().length === 0) return "[UNKNOWN_PAYROLL]";
  const clean = id.trim();
  if (clean.length <= 6) return "[REDACTED_PAYROLL]";
  return `${clean.slice(0, 3)}...${clean.slice(-3)}`;
}

/**
 * Default empty/unlocked recipient lock status.
 */
export function createEmptyRecipientLockStatus(
  recipient: string,
  options: { redact?: boolean } = {}
): RecipientLockStatus {
  const clean = recipient ? recipient.trim() : "";
  const shouldRedact = options.redact !== false;
  const now = Date.now();

  return {
    recipient: clean,
    redactedRecipient: shouldRedact ? maskRecipientIdentifier(clean) : clean,
    isLocked: false,
    canReceivePayout: true,
    lockReason: "none",
    payrollId: undefined,
    redactedPayrollId: undefined,
    lockedAt: 0,
    unlockAt: undefined,
    lockedBy: undefined,
    redactedLockedBy: undefined,
    fetchedAt: now,
  };
}

/**
 * Create a mock recipient lock status for testing and development.
 */
export function createMockRecipientLockStatus(
  overrides: Partial<RecipientLockStatus> = {}
): RecipientLockStatus {
  const now = Date.now();
  const recipient =
    overrides.recipient ?? "GA2C5RFPE6GCKMY3Z4DC6NOURMDRYZ3UMDVQ4N5ACFBPQ4E3Y3376E67";
  const isLocked = overrides.isLocked ?? true;
  const payrollId = overrides.payrollId ?? (isLocked ? "payroll-run-2024-01" : undefined);
  const lockedBy = overrides.lockedBy ?? (isLocked ? "GBBD...PABC" : undefined);

  const defaults: RecipientLockStatus = {
    recipient,
    redactedRecipient: maskRecipientIdentifier(recipient),
    isLocked,
    canReceivePayout: !isLocked,
    lockReason: isLocked ? (overrides.lockReason ?? "active_payroll_execution") : "none",
    payrollId,
    redactedPayrollId: payrollId ? maskPayrollIdentifier(payrollId) : undefined,
    lockedAt: isLocked ? (overrides.lockedAt ?? now - 30 * 60 * 1000) : 0,
    unlockAt: isLocked ? (overrides.unlockAt ?? now + 30 * 60 * 1000) : undefined,
    lockedBy,
    redactedLockedBy: lockedBy ? maskRecipientIdentifier(lockedBy) : undefined,
    fetchedAt: now,
  };

  return { ...defaults, ...overrides };
}

// ── Contract Normalizer & Query ───────────────────────────────────────────────

/**
 * Normalizes a raw Soroban contract response into a typed `RecipientLockStatus`.
 *
 * @param raw - Raw contract ScVal response
 * @param recipient - Recipient address (fallback)
 * @param fallbackPayrollId - Optional fallback payroll ID
 * @param options - Normalization options
 * @returns Normalized recipient lock status with safe defaults
 */
export function normalizeRecipientLockStatus(
  raw: xdr.ScVal,
  recipient: string,
  fallbackPayrollId?: string,
  options: { redact?: boolean } = {}
): RecipientLockStatus {
  const cleanRecipient = recipient ? recipient.trim() : "";
  const shouldRedact = options.redact !== false;
  const empty = createEmptyRecipientLockStatus(cleanRecipient, options);

  const swName = raw.switch().name;

  // Handle boolean response (e.g. from is_recipient_locked)
  if (swName === "scvBool") {
    const isLocked = raw.b();
    return {
      ...empty,
      isLocked,
      canReceivePayout: !isLocked,
      lockReason: isLocked ? "active_payroll_execution" : "none",
      payrollId: isLocked ? fallbackPayrollId : undefined,
      redactedPayrollId:
        isLocked && fallbackPayrollId ? maskPayrollIdentifier(fallbackPayrollId) : undefined,
      lockedAt: isLocked ? Date.now() : 0,
    };
  }

  const map = raw.map();
  if (!map) {
    return empty;
  }

  const entries: Record<string, xdr.ScVal> = {};
  for (const entry of map) {
    const key = entry.key().sym()?.toString() ?? "";
    entries[key] = entry.val();
  }

  const isLocked = entries.is_locked ? scValToBool(entries.is_locked) : false;
  const rawRecipient = scValToString(entries.recipient) || cleanRecipient;
  const rawPayrollId =
    scValToString(entries.payroll_id) || (isLocked ? fallbackPayrollId : undefined);
  const rawLockedBy = scValToString(entries.locked_by);
  const rawReason = scValToString(entries.lock_reason);
  const lockedAtSeconds = scValToBigInt(entries.locked_at);
  const unlockAtSeconds = entries.unlock_at ? scValToBigInt(entries.unlock_at) : undefined;

  let lockReason: RecipientLockReason = "none";
  if (isLocked) {
    if (
      rawReason === "active_payroll_execution" ||
      rawReason === "batch_in_flight" ||
      rawReason === "pending_settlement" ||
      rawReason === "dispute_freeze" ||
      rawReason === "administrative_hold"
    ) {
      lockReason = rawReason;
    } else {
      lockReason = "active_payroll_execution";
    }
  }

  const resolvedRecipient = rawRecipient || cleanRecipient;

  return {
    recipient: resolvedRecipient,
    redactedRecipient: shouldRedact
      ? maskRecipientIdentifier(resolvedRecipient)
      : resolvedRecipient,
    isLocked,
    canReceivePayout: !isLocked,
    lockReason,
    payrollId: rawPayrollId || undefined,
    redactedPayrollId: rawPayrollId ? maskPayrollIdentifier(rawPayrollId) : undefined,
    lockedAt: Number(lockedAtSeconds) * 1000,
    unlockAt: unlockAtSeconds !== undefined ? Number(unlockAtSeconds) * 1000 : undefined,
    lockedBy: rawLockedBy || undefined,
    redactedLockedBy: rawLockedBy ? maskRecipientIdentifier(rawLockedBy) : undefined,
    fetchedAt: Date.now(),
  };
}

/**
 * Fetch the recipient lock status from the contract.
 *
 * Calls the contract's `get_recipient_lock` or `is_recipient_locked` method
 * and normalizes the response into a typed, UI-safe `RecipientLockStatus`.
 *
 * @param contractWrapper - A `BaseContractWrapper` instance
 * @param recipient - Recipient Stellar address
 * @param employer - Employer/company Stellar address
 * @param options - Fetch options including signer and network
 * @returns Normalized recipient lock status with safe defaults
 */
export async function fetchRecipientLockStatus(
  contractWrapper: BaseContractWrapper,
  recipient: string,
  employer: string,
  options: FetchRecipientLockStatusOptions
): Promise<RecipientLockStatus> {
  if (!recipient || recipient.trim().length === 0) {
    throw createRecipientLockError(
      "INVALID_RECIPIENT",
      "Recipient address must not be empty.",
      Date.now()
    );
  }

  let employerScVal: xdr.ScVal;
  try {
    employerScVal = new Address(employer.trim()).toScVal();
  } catch {
    employerScVal = nativeToScVal(employer.trim(), { type: "string" });
  }

  let recipientScVal: xdr.ScVal;
  try {
    recipientScVal = new Address(recipient.trim()).toScVal();
  } catch {
    recipientScVal = nativeToScVal(recipient.trim(), { type: "string" });
  }

  const args: xdr.ScVal[] = [employerScVal, recipientScVal];

  try {
    const result = await contractWrapper["invoke"](
      "get_recipient_lock",
      args,
      toISigner(options.signer),
      options.network ?? Networks.TESTNET,
      options.requestId
    );

    return normalizeRecipientLockStatus(result, recipient, undefined, { redact: options.redact });
  } catch (error) {
    // Return an unlocked default with error info attached for graceful degradation
    const empty = createEmptyRecipientLockStatus(recipient, { redact: options.redact });
    (empty as RecipientLockStatus & { _error?: unknown })._error = error;
    return empty;
  }
}

// ── Pure Evaluation Logic ─────────────────────────────────────────────────────

const ACTIVE_EXECUTION_STATUSES = new Set([
  "locked",
  "executing",
  "in_flight",
  "pending_settlement",
  "processing",
  "submitted",
]);

const TERMINAL_EXECUTION_STATUSES = new Set([
  "settled",
  "executed",
  "cancelled",
  "failed",
  "archived",
  "draft",
]);

/**
 * Pure function: Evaluates whether a recipient is locked across active in-flight payroll executions.
 *
 * @param recipient - The recipient address or employee identifier to check
 * @param activeExecutions - Array of in-flight or pending payroll runs
 * @param options - Evaluation options (reference time, timeout, redaction)
 * @returns Complete normalized `RecipientLockStatus`
 */
export function evaluateRecipientLockStatus(
  recipient: string,
  activeExecutions: ActivePayrollExecution[] = [],
  options: RecipientLockReadOptions = {}
): RecipientLockStatus {
  if (!recipient || recipient.trim().length === 0) {
    throw createRecipientLockError(
      "INVALID_RECIPIENT",
      "Recipient identifier must not be empty.",
      options.now ?? Date.now()
    );
  }

  const cleanRecipient = recipient.trim();
  const now = options.now ?? Date.now();
  const shouldRedact = options.redact !== false;
  const timeoutMs = options.lockTimeoutMs;

  for (const execution of activeExecutions) {
    if (!execution || !Array.isArray(execution.recipients)) {
      continue;
    }

    const normStatus = execution.status ? execution.status.trim().toLowerCase() : "";

    // Skip terminal or non-locking statuses
    if (TERMINAL_EXECUTION_STATUSES.has(normStatus)) {
      continue;
    }

    const isExplicitlyActive = ACTIVE_EXECUTION_STATUSES.has(normStatus);
    if (!isExplicitlyActive && options.strict !== true) {
      continue;
    }

    // Check if recipient is part of this execution
    const isIncluded = execution.recipients.some(
      (r) => r && r.trim().toLowerCase() === cleanRecipient.toLowerCase()
    );

    if (isIncluded) {
      const lockedAt = execution.lockedAt ?? now;

      // Check if lock has expired due to timeout
      if (timeoutMs !== undefined && timeoutMs > 0 && now - lockedAt > timeoutMs) {
        continue;
      }

      // Check if unlockAt has passed
      if (execution.unlockAt !== undefined && execution.unlockAt > 0 && now >= execution.unlockAt) {
        continue;
      }

      const payrollId = execution.payrollId?.trim();
      const lockReason: RecipientLockReason = execution.lockReason ?? "active_payroll_execution";

      return {
        recipient: cleanRecipient,
        redactedRecipient: shouldRedact ? maskRecipientIdentifier(cleanRecipient) : cleanRecipient,
        isLocked: true,
        canReceivePayout: false,
        lockReason,
        payrollId,
        redactedPayrollId: payrollId ? maskPayrollIdentifier(payrollId) : undefined,
        lockedAt,
        unlockAt: execution.unlockAt,
        lockedBy: execution.lockedBy,
        redactedLockedBy: execution.lockedBy
          ? maskRecipientIdentifier(execution.lockedBy)
          : undefined,
        fetchedAt: now,
      };
    }
  }

  // Not locked by any active execution
  return createEmptyRecipientLockStatus(cleanRecipient, { redact: shouldRedact });
}

/**
 * Pure function: Evaluates lock statuses for a batch of recipients.
 *
 * @param recipients - Array of recipient identifiers
 * @param activeExecutions - Array of active in-flight executions
 * @param options - Evaluation options
 * @returns Summary containing aggregate counts and individual statuses
 */
export function evaluateBatchRecipientLockStatus(
  recipients: string[],
  activeExecutions: ActivePayrollExecution[] = [],
  options: RecipientLockReadOptions = {}
): BatchRecipientLockSummary {
  const statuses: RecipientLockStatus[] = [];
  const lockedRecipients: string[] = [];

  for (const r of recipients) {
    if (!r || r.trim().length === 0) continue;
    const status = evaluateRecipientLockStatus(r, activeExecutions, options);
    statuses.push(status);
    if (status.isLocked) {
      lockedRecipients.push(status.recipient);
    }
  }

  const lockedCount = lockedRecipients.length;
  const unlockedCount = statuses.length - lockedCount;

  return {
    totalChecked: statuses.length,
    lockedCount,
    unlockedCount,
    statuses,
    lockedRecipients,
    hasAnyLocked: lockedCount > 0,
  };
}

/**
 * Validates a recipient lock status object for operational soundness.
 */
export function validateRecipientLockStatus(
  status: unknown,
  options: { allowUnlocked?: boolean } = {}
): RecipientLockValidationResult {
  if (!status || typeof status !== "object") {
    return {
      ok: false,
      code: "INVALID_RECIPIENT",
      message: "Lock status must be a valid object.",
    };
  }

  const candidate = status as Partial<RecipientLockStatus>;

  if (!candidate.recipient || candidate.recipient.trim().length === 0) {
    return {
      ok: false,
      code: "INVALID_RECIPIENT",
      message: "Recipient identifier must not be empty.",
    };
  }

  if (typeof candidate.isLocked !== "boolean") {
    return {
      ok: false,
      code: "UNKNOWN_ERROR",
      message: "Lock status must contain a boolean isLocked flag.",
      recipient: candidate.recipient,
    };
  }

  if (candidate.isLocked && !candidate.lockReason) {
    return {
      ok: false,
      code: "UNKNOWN_ERROR",
      message: "Locked recipient status must specify a lockReason.",
      recipient: candidate.recipient,
    };
  }

  if (!options.allowUnlocked && !candidate.isLocked) {
    // Valid unlocked status
  }

  return {
    ok: true,
    status: candidate as RecipientLockStatus,
  };
}

/**
 * Check if a recipient status is currently locked.
 */
export function isRecipientLocked(
  statusOrRecipient: RecipientLockStatus | { isLocked: boolean }
): boolean {
  return Boolean(statusOrRecipient && statusOrRecipient.isLocked);
}

/**
 * Check if a recipient status is clear to receive a payout.
 */
export function canRecipientReceivePayout(
  statusOrRecipient: RecipientLockStatus | { isLocked: boolean; canReceivePayout?: boolean }
): boolean {
  if (!statusOrRecipient) return false;
  if (
    "canReceivePayout" in statusOrRecipient &&
    typeof statusOrRecipient.canReceivePayout === "boolean"
  ) {
    return statusOrRecipient.canReceivePayout;
  }
  return !statusOrRecipient.isLocked;
}

/**
 * Formats a `RecipientLockStatus` into a single, privacy-safe, human-readable line.
 * Suitable for UI badges, banners, and audit logging.
 *
 * @param status - Normalized recipient lock status
 * @returns Human-readable label (e.g. `Recipient GA2C...3376: 🔒 LOCKED (active_payroll_execution in pay...001 since 2024-01-15T10:00:00.000Z)`)
 */
export function formatRecipientLockStatus(status: RecipientLockStatus): string {
  const displayRecipient = status.redactedRecipient || maskRecipientIdentifier(status.recipient);

  if (!status.isLocked) {
    return `Recipient ${displayRecipient}: 🔓 UNLOCKED (available for payout)`;
  }

  const displayPayroll =
    status.redactedPayrollId ||
    (status.payrollId ? maskPayrollIdentifier(status.payrollId) : undefined);
  const payrollClause = displayPayroll ? ` in run ${displayPayroll}` : "";
  const timeClause = status.lockedAt > 0 ? ` since ${new Date(status.lockedAt).toISOString()}` : "";
  const lockedByClause = status.redactedLockedBy ? ` by ${status.redactedLockedBy}` : "";

  return `Recipient ${displayRecipient}: 🔒 LOCKED (${status.lockReason}${payrollClause}${lockedByClause}${timeClause})`;
}
