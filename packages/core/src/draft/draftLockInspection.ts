/**
 * Payroll Draft Lock Inspection Helper (#537)
 *
 * Inspects a payroll draft's lock readiness and operational lock state before
 * submission or settlement. Evaluates whether a draft can be safely locked,
 * whether it is already locked or expired, and whether any payout recipients
 * are locked by in-flight active payroll executions.
 *
 * ## Privacy & Security Guarantees
 * - Salary amounts and individual compensation figures are NEVER included
 *   in blocker messages, warnings, summaries, or errors.
 * - Recipient addresses and internal draft identifiers are automatically
 *   masked/redacted by default (`GA2C...6E67`, `EMP***5`).
 * - Reason and blocker codes follow standardized operational enums.
 */

import type { PayrollDraft, PayrollDraftEntry } from "./types";
import { DraftBuilder } from "./DraftBuilder";
import { computeDraftChecksum } from "./draftChecksum";
import {
  evaluateRecipientLockStatus,
  maskRecipientIdentifier,
  type ActivePayrollExecution,
  type RecipientLockStatus,
} from "../payroll/recipientLockStatus";
import { maskStellarAddress, maskEmployeeId } from "../issues/exportSanitizer";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Operational lock state of a payroll draft.
 */
export type DraftLockState = "unlocked" | "locked" | "pending_lock" | "expired" | "invalid";

/**
 * Structured error and blocker codes for draft lock inspection.
 */
export type DraftLockErrorCode =
  | "DRAFT_ALREADY_LOCKED"
  | "DRAFT_EMPTY"
  | "DRAFT_EXPIRED"
  | "RECIPIENT_LOCKED"
  | "INVALID_RECIPIENT"
  | "INVALID_AMOUNT"
  | "MISSING_ASSET"
  | "DUPLICATE_RECIPIENT"
  | "CHECKSUM_MISMATCH"
  | "UNAUTHORIZED_LOCKER"
  | "INVALID_DRAFT_STATE";

/**
 * Structured warning codes for draft lock inspection.
 */
export type DraftLockWarningCode =
  "MIXED_ASSETS" | "LARGE_DRAFT" | "EMPTY_NOTE" | "EXPIRING_SOON" | "CUSTOM_WARNING";

/**
 * A blocking issue preventing a draft from being locked.
 */
export interface DraftLockBlocker {
  /** Machine-readable error code */
  code: DraftLockErrorCode;
  /** Privacy-safe human-readable message */
  message: string;
  /** Field name associated with the blocker */
  field?: string;
  /** Entry index if associated with a specific payment */
  index?: number;
  /** Redacted recipient identifier if applicable */
  recipient?: string;
}

/**
 * Non-blocking advisory warning for a payroll draft.
 */
export interface DraftLockWarning {
  /** Machine-readable warning code */
  code: DraftLockWarningCode;
  /** Privacy-safe advisory message */
  message: string;
  /** Field name associated with the warning */
  field?: string;
  /** Entry index if associated with a specific payment */
  index?: number;
}

/**
 * Comprehensive draft lock inspection report.
 */
export interface DraftLockInspectionResult {
  /** Human-readable draft label or identifier, if specified */
  draftLabel?: string;
  /** Redacted draft label safe for external logs */
  redactedDraftLabel?: string;
  /** Whether the draft is currently in a locked state */
  isLocked: boolean;
  /** Whether the draft is clear to be locked and submitted */
  canLock: boolean;
  /** Evaluated operational lock state */
  lockState: DraftLockState;
  /** Total number of payment entries in the draft */
  entryCount: number;
  /** Total unique recipient count */
  uniqueRecipientCount: number;
  /** Number of recipients in the draft that are currently locked */
  lockedRecipientCount: number;
  /** Redacted identifiers of all locked recipients */
  lockedRecipients: string[];
  /** Distinct assets present in the draft */
  assets: string[];
  /** List of blocking issues that prevent locking */
  blockers: DraftLockBlocker[];
  /** List of non-blocking advisory warnings */
  warnings: DraftLockWarning[];
  /** Single-line human-readable summary badge */
  summary: string;
  /** Unix timestamp when inspection was performed (ms) */
  inspectedAt: number;
  /** Unix timestamp when the draft was locked (ms), if locked */
  lockedAt?: number;
  /** Unix timestamp when the lock expires (ms), if configured */
  expiresAt?: number;
  /** Operator or authorizer who locked the draft, if recorded */
  lockedBy?: string;
  /** Redacted locked-by identifier */
  redactedLockedBy?: string;
  /** Computed canonical SHA-256 checksum of the draft */
  checksum?: string;
}

/**
 * Options configuring payroll draft lock inspection.
 */
export interface DraftLockInspectionOptions {
  /** Reference timestamp in epoch ms (defaults to Date.now()) */
  now?: number;
  /** In-flight active payroll executions to cross-check recipient locks against */
  activeExecutions?: ActivePayrollExecution[];
  /** Pre-resolved recipient lock statuses to evaluate */
  recipientLockStatuses?: RecipientLockStatus[];
  /** Maximum lock duration in ms after which draft locks are considered expired */
  lockTimeoutMs?: number;
  /** Expected draft checksum to verify against */
  expectedChecksum?: string;
  /** Account or operator attempting to perform the lock */
  authorizer?: string;
  /** List of authorized accounts permitted to lock this draft */
  allowedAuthorizers?: string[];
  /** Whether the draft is already marked as locked */
  isAlreadyLocked?: boolean;
  /** Timestamp when draft was locked (ms) */
  lockedAt?: number;
  /** Expiration timestamp for the draft or lock (ms) */
  expiresAt?: number;
  /** Address of operator who placed the lock */
  lockedBy?: string;
  /** Mask identifiers in outputs (defaults to true) */
  redact?: boolean;
  /** Treat warnings as blockers in strict mode (defaults to false) */
  strict?: boolean;
}

// ── Error Class ───────────────────────────────────────────────────────────────

/**
 * Exception thrown when a draft fails lock inspection assertion.
 */
export class DraftLockError extends Error {
  readonly code: DraftLockErrorCode;
  readonly blockers: DraftLockBlocker[];

  constructor(message: string, code: DraftLockErrorCode, blockers: DraftLockBlocker[] = []) {
    super(message);
    this.name = "DraftLockError";
    this.code = code;
    this.blockers = blockers;
    Object.setPrototypeOf(this, DraftLockError.prototype);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function redactLabel(label?: string): string | undefined {
  if (!label || label.trim().length === 0) return undefined;
  const clean = label.trim();
  if (clean.length <= 4) return "[REDACTED_LABEL]";
  return `${clean.slice(0, 3)}...${clean.slice(-3)}`;
}

function coerceToDraft(input: PayrollDraft | PayrollDraftEntry[] | DraftBuilder | unknown): {
  draft: PayrollDraft;
  isBuilder: boolean;
} {
  if (input instanceof DraftBuilder) {
    try {
      const draft = input.build();
      return { draft, isBuilder: true };
    } catch {
      // Build failed; construct raw draft snapshot from builder entries
      const summary = input.summary();
      const rawDraft: PayrollDraft = {
        version: 1,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        entries: (input as unknown as { entries: PayrollDraftEntry[] }).entries ?? [],
      };
      return { draft: rawDraft, isBuilder: true };
    }
  }

  if (Array.isArray(input)) {
    const now = new Date().toISOString();
    return {
      draft: {
        version: 1,
        createdAt: now,
        updatedAt: now,
        entries: input as PayrollDraftEntry[],
      },
      isBuilder: false,
    };
  }

  if (
    input &&
    typeof input === "object" &&
    "entries" in input &&
    Array.isArray((input as PayrollDraft).entries)
  ) {
    return { draft: input as PayrollDraft, isBuilder: false };
  }

  // Fallback for null / undefined / unknown object
  const now = new Date().toISOString();
  return {
    draft: {
      version: 1,
      createdAt: now,
      updatedAt: now,
      entries: [],
    },
    isBuilder: false,
  };
}

// ── Inspection Implementation ─────────────────────────────────────────────────

const LARGE_DRAFT_LIMIT = 500;

/**
 * Inspects a payroll draft for lock readiness and operational lock status.
 *
 * Evaluates whether a draft can safely be locked, whether it is already locked or
 * expired, whether any recipients are locked by active runs, and whether draft
 * integrity and authorizer requirements are met.
 *
 * @param draftOrEntries - The `PayrollDraft`, `DraftBuilder`, or array of `PayrollDraftEntry` to inspect
 * @param options - Inspection options (activeExecutions, checksum, authorizer, timeout)
 * @returns Complete, privacy-safe `DraftLockInspectionResult`
 *
 * @example
 * ```typescript
 * const result = inspectDraftLock(payrollDraft, {
 *   activeExecutions: inFlightRuns,
 *   expectedChecksum: "a1b2c3...",
 * });
 *
 * if (!result.canLock) {
 *   console.error("Draft cannot be locked:", result.blockers);
 * }
 * ```
 */
export function inspectDraftLock(
  draftOrEntries: PayrollDraft | PayrollDraftEntry[] | DraftBuilder | unknown,
  options: DraftLockInspectionOptions = {}
): DraftLockInspectionResult {
  const now = options.now ?? Date.now();
  const shouldRedact = options.redact !== false;
  const { draft } = coerceToDraft(draftOrEntries);

  const blockers: DraftLockBlocker[] = [];
  const warnings: DraftLockWarning[] = [];
  const entries = draft.entries ?? [];

  const draftLabel = draft.label?.trim();
  const redactedDraftLabel = shouldRedact ? redactLabel(draftLabel) : draftLabel;

  // 1. Check if draft is empty
  if (entries.length === 0) {
    blockers.push({
      code: "DRAFT_EMPTY",
      message: "Payroll draft is empty; at least one payment entry is required to lock.",
      field: "entries",
    });
  }

  // 2. Check if draft is already marked locked
  const isAlreadyLocked = options.isAlreadyLocked ?? false;
  const lockedAt = options.lockedAt ?? (isAlreadyLocked ? now : undefined);
  const expiresAt = options.expiresAt;
  const lockedBy = options.lockedBy?.trim();
  const redactedLockedBy = lockedBy
    ? shouldRedact
      ? maskRecipientIdentifier(lockedBy)
      : lockedBy
    : undefined;

  let isExpired = false;
  if (expiresAt !== undefined && expiresAt > 0 && now >= expiresAt) {
    isExpired = true;
    blockers.push({
      code: "DRAFT_EXPIRED",
      message: "Payroll draft has expired and can no longer be locked or submitted.",
      field: "expiresAt",
    });
  } else if (
    lockedAt !== undefined &&
    options.lockTimeoutMs !== undefined &&
    options.lockTimeoutMs > 0 &&
    now - lockedAt > options.lockTimeoutMs
  ) {
    isExpired = true;
    blockers.push({
      code: "DRAFT_EXPIRED",
      message: "Payroll draft lock duration has exceeded configured timeout limit.",
      field: "lockTimeoutMs",
    });
  }

  if (isAlreadyLocked && !isExpired) {
    blockers.push({
      code: "DRAFT_ALREADY_LOCKED",
      message: "Payroll draft is already locked and cannot be locked again.",
      field: "isAlreadyLocked",
    });
  }

  // 3. Check authorizer authorization if configured
  if (options.authorizer !== undefined && options.authorizer.trim() !== "") {
    const authorizerClean = options.authorizer.trim();
    if (options.allowedAuthorizers && options.allowedAuthorizers.length > 0) {
      const isAllowed = options.allowedAuthorizers.some(
        (a) => a && a.trim().toLowerCase() === authorizerClean.toLowerCase()
      );
      if (!isAllowed) {
        blockers.push({
          code: "UNAUTHORIZED_LOCKER",
          message: "Authorizer is not permitted to lock this payroll draft.",
          field: "authorizer",
        });
      }
    }
  }

  // 4. Validate entries & collect recipients
  const seenRecipients = new Map<string, number>();
  const distinctAssets = new Set<string>();
  const recipientList: string[] = [];

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry || typeof entry !== "object") {
      blockers.push({
        code: "INVALID_DRAFT_STATE",
        message: "Entry is not a valid payment object.",
        field: "entries",
        index: i,
      });
      continue;
    }

    const rawRecipient = typeof entry.recipientId === "string" ? entry.recipientId.trim() : "";
    const maskedRecip = shouldRedact ? maskRecipientIdentifier(rawRecipient) : rawRecipient;

    if (!rawRecipient) {
      blockers.push({
        code: "INVALID_RECIPIENT",
        message: "Recipient identifier is missing or empty.",
        field: "recipientId",
        index: i,
      });
    } else {
      const lowerRecip = rawRecipient.toLowerCase();
      const prevIdx = seenRecipients.get(lowerRecip);
      if (prevIdx !== undefined) {
        blockers.push({
          code: "DUPLICATE_RECIPIENT",
          message: `Duplicate recipient detected at entry indices ${prevIdx} and ${i}.`,
          field: "recipientId",
          index: i,
          recipient: maskedRecip,
        });
      } else {
        seenRecipients.set(lowerRecip, i);
        recipientList.push(rawRecipient);
      }
    }

    const rawAmount = typeof entry.amount === "string" ? entry.amount.trim() : "";
    let amountValid = false;
    try {
      const parsed = BigInt(rawAmount === "" ? "0" : rawAmount);
      amountValid = parsed > 0n;
    } catch {
      amountValid = false;
    }

    if (!amountValid) {
      blockers.push({
        code: "INVALID_AMOUNT",
        message: "Payment amount must be a positive integer in base units.",
        field: "amount",
        index: i,
        recipient: maskedRecip || undefined,
      });
    }

    const rawAsset = typeof entry.asset === "string" ? entry.asset.trim() : "";
    if (!rawAsset) {
      blockers.push({
        code: "MISSING_ASSET",
        message: "Payment asset code is required.",
        field: "asset",
        index: i,
      });
    } else {
      distinctAssets.add(rawAsset);
    }

    if (entry.note !== undefined && entry.note.trim() === "") {
      warnings.push({
        code: "EMPTY_NOTE",
        message: "Empty note will be excluded from final serialization.",
        field: "note",
        index: i,
      });
    }
  }

  // 5. Check warnings for assets and size
  if (distinctAssets.size > 1) {
    const assetStr = Array.from(distinctAssets).sort().join(", ");
    warnings.push({
      code: "MIXED_ASSETS",
      message: `Draft contains multiple payment assets (${assetStr}); verify single-asset batch requirements.`,
      field: "asset",
    });
  }

  if (entries.length > LARGE_DRAFT_LIMIT) {
    warnings.push({
      code: "LARGE_DRAFT",
      message: `Draft contains ${entries.length} entries; consider submitting in sequential batches for safety.`,
      field: "entries",
    });
  }

  // 6. Check recipient locks against active in-flight executions or pre-resolved statuses
  const lockedRecipients: string[] = [];
  const activeExecs = options.activeExecutions ?? [];
  const preResolvedStatuses = options.recipientLockStatuses ?? [];

  // Index pre-resolved statuses
  const preResolvedMap = new Map<string, RecipientLockStatus>();
  for (const st of preResolvedStatuses) {
    if (st && st.recipient) {
      preResolvedMap.set(st.recipient.trim().toLowerCase(), st);
    }
  }

  for (const recip of recipientList) {
    const lowerRecip = recip.toLowerCase();
    const maskedRecip = shouldRedact ? maskRecipientIdentifier(recip) : recip;

    // Check pre-resolved status first
    const preResolved = preResolvedMap.get(lowerRecip);
    if (preResolved && preResolved.isLocked) {
      lockedRecipients.push(maskedRecip);
      blockers.push({
        code: "RECIPIENT_LOCKED",
        message: `Recipient ${maskedRecip} is locked by an active payroll run (${preResolved.lockReason}).`,
        field: "recipientId",
        recipient: maskedRecip,
      });
      continue;
    }

    // Evaluate against active in-flight executions
    if (activeExecs.length > 0) {
      const evalStatus = evaluateRecipientLockStatus(recip, activeExecs, {
        now,
        lockTimeoutMs: options.lockTimeoutMs,
        redact: shouldRedact,
      });

      if (evalStatus.isLocked) {
        lockedRecipients.push(maskedRecip);
        blockers.push({
          code: "RECIPIENT_LOCKED",
          message: `Recipient ${maskedRecip} is locked by active payroll execution ${evalStatus.redactedPayrollId ?? "[ACTIVE_RUN]"}.`,
          field: "recipientId",
          recipient: maskedRecip,
        });
      }
    }
  }

  // 7. Check draft checksum if expected checksum provided
  let computedChecksum: string | undefined;
  if (entries.length > 0) {
    try {
      computedChecksum = computeDraftChecksum(draft);
      if (
        options.expectedChecksum !== undefined &&
        options.expectedChecksum.trim() !== "" &&
        computedChecksum.toLowerCase().trim() !== options.expectedChecksum.toLowerCase().trim()
      ) {
        blockers.push({
          code: "CHECKSUM_MISMATCH",
          message: "Draft checksum does not match expected reference checksum.",
          field: "checksum",
        });
      }
    } catch {
      // Checksum calculation skipped if draft structure unparseable
    }
  }

  // Determine lockState and canLock
  let lockState: DraftLockState = "unlocked";
  if (isExpired) {
    lockState = "expired";
  } else if (isAlreadyLocked) {
    lockState = "locked";
  } else if (blockers.length > 0) {
    lockState = "invalid";
  } else {
    lockState = "unlocked";
  }

  const canLock = blockers.length === 0 && !isAlreadyLocked && !isExpired;

  const result: DraftLockInspectionResult = {
    draftLabel,
    redactedDraftLabel,
    isLocked: isAlreadyLocked && !isExpired,
    canLock,
    lockState,
    entryCount: entries.length,
    uniqueRecipientCount: seenRecipients.size,
    lockedRecipientCount: lockedRecipients.length,
    lockedRecipients,
    assets: Array.from(distinctAssets).sort(),
    blockers,
    warnings,
    summary: "",
    inspectedAt: now,
    lockedAt,
    expiresAt,
    lockedBy,
    redactedLockedBy,
    checksum: computedChecksum,
  };

  result.summary = formatDraftLockInspectionSummary(result);
  return result;
}

/**
 * Formats a `DraftLockInspectionResult` into a concise, privacy-safe single-line summary.
 *
 * @param result - The inspection result to format
 * @returns Human-readable label (e.g. `Draft (pay...-01): ✅ LOCK READY | 10 entries | 10 recipients`)
 */
export function formatDraftLockInspectionSummary(result: DraftLockInspectionResult): string {
  const labelClause = result.redactedDraftLabel
    ? `Draft (${result.redactedDraftLabel})`
    : "Payroll Draft";

  let statusBadge: string;
  if (result.isLocked) {
    statusBadge = "🔒 LOCKED";
  } else if (result.lockState === "expired") {
    statusBadge = "⚠️ EXPIRED";
  } else if (result.canLock) {
    statusBadge = "✅ LOCK READY";
  } else {
    statusBadge = `🛑 BLOCKED (${result.blockers.length} issue${result.blockers.length === 1 ? "" : "s"})`;
  }

  const parts = [
    `${labelClause}: ${statusBadge}`,
    `${result.entryCount} entries`,
    `${result.uniqueRecipientCount} recipients`,
  ];

  if (result.lockedRecipientCount > 0) {
    parts.push(`⚠️ ${result.lockedRecipientCount} locked`);
  }

  if (result.assets.length > 0) {
    parts.push(`assets: ${result.assets.join(", ")}`);
  }

  return parts.join(" | ");
}

/**
 * Asserts that a draft is clear to be locked and submitted.
 * Throws a `DraftLockError` with structured blocker details if inspection fails.
 *
 * @param draftOrEntries - The payroll draft to inspect
 * @param options - Inspection options
 * @throws {DraftLockError} If the draft cannot be locked
 */
export function assertDraftLockable(
  draftOrEntries: PayrollDraft | PayrollDraftEntry[] | DraftBuilder | unknown,
  options: DraftLockInspectionOptions = {}
): void {
  const result = inspectDraftLock(draftOrEntries, options);
  if (!result.canLock) {
    const firstBlocker = result.blockers[0];
    const code = firstBlocker ? firstBlocker.code : "INVALID_DRAFT_STATE";
    const msg = firstBlocker
      ? `Draft lock assertion failed: [${firstBlocker.code}] ${firstBlocker.message}`
      : "Draft lock assertion failed: draft is not in a lockable state.";

    throw new DraftLockError(msg, code, result.blockers);
  }
}

/**
 * Returns true if a draft is ready and clear to be locked.
 */
export function isDraftLockable(
  draftOrEntries: PayrollDraft | PayrollDraftEntry[] | DraftBuilder | unknown,
  options: DraftLockInspectionOptions = {}
): boolean {
  return inspectDraftLock(draftOrEntries, options).canLock;
}

/**
 * Creates a mock draft lock inspection result for testing and development.
 */
export function createMockDraftLockInspectionResult(
  overrides: Partial<DraftLockInspectionResult> = {}
): DraftLockInspectionResult {
  const now = Date.now();
  const canLock = overrides.canLock ?? true;
  const isLocked = overrides.isLocked ?? false;

  const defaults: DraftLockInspectionResult = {
    draftLabel: "Mock Payroll Draft",
    redactedDraftLabel: "Moc...aft",
    isLocked,
    canLock,
    lockState: isLocked ? "locked" : canLock ? "unlocked" : "invalid",
    entryCount: 2,
    uniqueRecipientCount: 2,
    lockedRecipientCount: 0,
    lockedRecipients: [],
    assets: ["native"],
    blockers: [],
    warnings: [],
    summary: "Payroll Draft: ✅ LOCK READY | 2 entries | 2 recipients | assets: native",
    inspectedAt: now,
    checksum: "a1b2c3d4e5f67890",
  };

  return { ...defaults, ...overrides };
}
