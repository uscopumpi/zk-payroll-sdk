/**
 * Draft Payroll Approval Snapshot Locking (#637)
 *
 * Implements immutable snapshot creation when a draft is approved, preventing
 * modifications after approval and ensuring snapshot integrity through checksums.
 *
 * ## Key Features
 * - Creates immutable snapshots on draft approval
 * - Prevents any modifications to approved/locked drafts
 * - Validates snapshot integrity using checksums
 * - Provides clear error messages for unauthorized modifications
 *
 * ## Privacy & Security
 * - Snapshots include full draft state at approval time
 * - Checksums ensure data integrity and tamper detection
 * - Approval metadata (timestamp, approver) are recorded
 */

import type { PayrollDraft } from "./types";
import { computeDraftChecksum } from "./draftChecksum";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Approval snapshot metadata recorded at the time of draft approval.
 */
export interface ApprovalMetadata {
  /** Unix timestamp when the draft was approved (ms) */
  approvedAt: number;
  /** Account or operator who approved the draft */
  approvedBy: string;
  /** SHA-256 checksum of the draft at approval time */
  checksum: string;
  /** Optional approval reason or note */
  reason?: string;
}

/**
 * Immutable snapshot of a draft at approval time.
 */
export interface DraftApprovalSnapshot {
  /** The draft state at approval time (immutable) */
  readonly draft: Readonly<PayrollDraft>;
  /** Approval metadata */
  readonly metadata: Readonly<ApprovalMetadata>;
  /** Snapshot version for future compatibility */
  readonly version: number;
}

/**
 * Error codes for approval snapshot operations.
 */
export type ApprovalSnapshotErrorCode =
  | "DRAFT_ALREADY_APPROVED"
  | "DRAFT_LOCKED"
  | "MODIFICATION_NOT_ALLOWED"
  | "INVALID_APPROVER"
  | "CHECKSUM_MISMATCH"
  | "SNAPSHOT_NOT_FOUND"
  | "INVALID_SNAPSHOT_STATE";

/**
 * Structured error for approval snapshot operations.
 */
export class ApprovalSnapshotError extends Error {
  constructor(
    public readonly code: ApprovalSnapshotErrorCode,
    message: string,
    public readonly field?: string
  ) {
    super(message);
    this.name = "ApprovalSnapshotError";
  }
}

// ── Snapshot Creation ─────────────────────────────────────────────────────────

/**
 * Creates an immutable approval snapshot of a draft.
 *
 * This function captures the current state of the draft along with approval
 * metadata including timestamp, approver, and checksum for integrity verification.
 *
 * @param draft - The draft to snapshot
 * @param approvedBy - Account or operator approving the draft
 * @param options - Optional configuration
 * @returns Immutable approval snapshot
 *
 * @throws ApprovalSnapshotError if draft is invalid or already approved
 *
 * @example
 * const snapshot = createApprovalSnapshot(draft, "GA2C5RFPE...", {
 *   reason: "Q1 2024 payroll approved"
 * });
 */
export function createApprovalSnapshot(
  draft: PayrollDraft,
  approvedBy: string,
  options?: {
    now?: number;
    reason?: string;
  }
): DraftApprovalSnapshot {
  // Validate inputs
  if (!draft || !draft.entries || draft.entries.length === 0) {
    throw new ApprovalSnapshotError(
      "INVALID_SNAPSHOT_STATE",
      "Cannot create approval snapshot: draft is empty or invalid",
      "entries"
    );
  }

  if (!approvedBy || approvedBy.trim() === "") {
    throw new ApprovalSnapshotError(
      "INVALID_APPROVER",
      "Cannot create approval snapshot: approver identifier is required",
      "approvedBy"
    );
  }

  const now = options?.now ?? Date.now();
  const checksum = computeDraftChecksum(draft);

  // Create deep frozen copy of draft to ensure immutability
  const frozenDraft = Object.freeze({
    ...draft,
    entries: Object.freeze(draft.entries.map((entry) => Object.freeze({ ...entry }))),
  }) as unknown as PayrollDraft;

  const metadata: ApprovalMetadata = {
    approvedAt: now,
    approvedBy: approvedBy.trim(),
    checksum,
    reason: options?.reason,
  };

  return Object.freeze({
    draft: frozenDraft,
    metadata: Object.freeze(metadata),
    version: 1,
  });
}

// ── Snapshot Validation ───────────────────────────────────────────────────────

/**
 * Verifies the integrity of an approval snapshot.
 *
 * Recomputes the checksum and compares it with the stored value to detect
 * any tampering or corruption.
 *
 * @param snapshot - The snapshot to validate
 * @returns true if snapshot is valid and intact
 *
 * @example
 * if (!validateApprovalSnapshot(snapshot)) {
 *   throw new Error("Snapshot integrity check failed");
 * }
 */
export function validateApprovalSnapshot(snapshot: DraftApprovalSnapshot): boolean {
  try {
    const currentChecksum = computeDraftChecksum(snapshot.draft as PayrollDraft);
    return currentChecksum === snapshot.metadata.checksum;
  } catch {
    return false;
  }
}

/**
 * Asserts that an approval snapshot is valid and throws if not.
 *
 * @param snapshot - The snapshot to validate
 * @throws ApprovalSnapshotError if snapshot is invalid or corrupted
 *
 * @example
 * assertValidApprovalSnapshot(snapshot);
 * // Continues only if snapshot is valid
 */
export function assertValidApprovalSnapshot(snapshot: DraftApprovalSnapshot): void {
  if (!validateApprovalSnapshot(snapshot)) {
    throw new ApprovalSnapshotError(
      "CHECKSUM_MISMATCH",
      "Approval snapshot integrity check failed: checksum mismatch detected",
      "checksum"
    );
  }
}

// ── Modification Prevention ───────────────────────────────────────────────────

/**
 * Checks if a draft has an active approval snapshot.
 *
 * @param draft - The draft to check
 * @param snapshot - Optional snapshot to verify against
 * @returns true if draft is approved and locked
 */
export function isDraftApproved(draft: PayrollDraft, snapshot?: DraftApprovalSnapshot): boolean {
  if (!snapshot) {
    return false;
  }

  const draftChecksum = computeDraftChecksum(draft);
  return draftChecksum === snapshot.metadata.checksum;
}

/**
 * Asserts that a draft is not approved and can be modified.
 *
 * @param draft - The draft to check
 * @param snapshot - Optional snapshot to verify against
 * @throws ApprovalSnapshotError if draft is approved/locked
 *
 * @example
 * assertDraftNotApproved(draft, existingSnapshot);
 * draft.entries.push(newEntry); // Safe to modify
 */
export function assertDraftNotApproved(
  draft: PayrollDraft,
  snapshot?: DraftApprovalSnapshot
): void {
  if (snapshot && isDraftApproved(draft, snapshot)) {
    throw new ApprovalSnapshotError(
      "MODIFICATION_NOT_ALLOWED",
      "Cannot modify draft: draft has been approved and is locked. " +
        `Approved at ${new Date(snapshot.metadata.approvedAt).toISOString()} ` +
        `by ${snapshot.metadata.approvedBy}`,
      "draft"
    );
  }
}

/**
 * Creates a guard function to prevent modifications to approved drafts.
 *
 * Returns a function that can be called before any draft modification
 * operation to ensure the draft is not locked.
 *
 * @param snapshot - The approval snapshot to guard against
 * @returns Guard function that throws if modification is attempted
 *
 * @example
 * const guardModification = createModificationGuard(snapshot);
 * guardModification(draft); // Throws if draft is approved
 */
export function createModificationGuard(
  snapshot?: DraftApprovalSnapshot
): (draft: PayrollDraft) => void {
  return (draft: PayrollDraft) => {
    assertDraftNotApproved(draft, snapshot);
  };
}

// ── Snapshot Export/Import ────────────────────────────────────────────────────

/**
 * Serializes an approval snapshot to JSON string.
 *
 * @param snapshot - The snapshot to serialize
 * @returns JSON string representation
 */
export function serializeApprovalSnapshot(snapshot: DraftApprovalSnapshot): string {
  return JSON.stringify({
    version: snapshot.version,
    draft: snapshot.draft,
    metadata: snapshot.metadata,
  });
}

/**
 * Deserializes an approval snapshot from JSON string.
 *
 * @param json - JSON string to parse
 * @returns Restored approval snapshot
 * @throws ApprovalSnapshotError if JSON is invalid or corrupted
 */
export function deserializeApprovalSnapshot(json: string): DraftApprovalSnapshot {
  try {
    const parsed = JSON.parse(json);

    if (!parsed.version || !parsed.draft || !parsed.metadata) {
      throw new Error("Invalid snapshot structure");
    }

    const snapshot: DraftApprovalSnapshot = Object.freeze({
      version: parsed.version,
      draft: Object.freeze({
        ...parsed.draft,
        entries: Object.freeze(parsed.draft.entries.map((e: any) => Object.freeze({ ...e }))),
      }),
      metadata: Object.freeze(parsed.metadata),
    });

    // Validate integrity after deserialization
    assertValidApprovalSnapshot(snapshot);

    return snapshot;
  } catch (error) {
    throw new ApprovalSnapshotError(
      "INVALID_SNAPSHOT_STATE",
      `Failed to deserialize approval snapshot: ${error instanceof Error ? error.message : "unknown error"}`,
      "snapshot"
    );
  }
}

// ── Snapshot Comparison ───────────────────────────────────────────────────────

/**
 * Compares a draft against its approval snapshot to detect modifications.
 *
 * @param draft - Current draft state
 * @param snapshot - Approval snapshot to compare against
 * @returns true if draft has been modified since approval
 */
export function hasBeenModifiedSinceApproval(
  draft: PayrollDraft,
  snapshot: DraftApprovalSnapshot
): boolean {
  const currentChecksum = computeDraftChecksum(draft);
  return currentChecksum !== snapshot.metadata.checksum;
}

/**
 * Returns a summary of approval snapshot status.
 *
 * @param snapshot - The approval snapshot
 * @returns Human-readable summary
 */
export function formatApprovalSnapshotSummary(snapshot: DraftApprovalSnapshot): string {
  const approvedDate = new Date(snapshot.metadata.approvedAt).toISOString();
  const entryCount = snapshot.draft.entries.length;
  const label = snapshot.draft.label || "Unlabeled Draft";

  return [
    "APPROVAL SNAPSHOT",
    `Draft: ${label}`,
    `Entries: ${entryCount}`,
    `Approved: ${approvedDate}`,
    `By: ${snapshot.metadata.approvedBy}`,
    `Checksum: ${snapshot.metadata.checksum.substring(0, 12)}...`,
    snapshot.metadata.reason ? `Reason: ${snapshot.metadata.reason}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}
