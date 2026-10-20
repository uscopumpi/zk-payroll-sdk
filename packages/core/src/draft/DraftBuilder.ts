import { DraftValidationFailedError } from "./DraftValidationFailedError";
import {
  DraftSummary,
  DraftValidationError,
  DraftValidationReport,
  DraftWarning,
  PayrollDraft,
  PayrollDraftEntry,
} from "./types";

const LARGE_DRAFT_THRESHOLD = 500;

/**
 * Fluent builder for composing, editing, and reviewing a payroll draft
 * before any signature or submission.
 *
 * Design goals (issue #64):
 * - Generate drafts without immediately submitting them.
 * - Expose programmatic validation feedback for UI rendering.
 * - Support review-first flows: structured summary + per-entry editing.
 *
 * Validation is non-mutating; both `validate()` and `summary()` can be
 * called at any time. `build()` returns an immutable `PayrollDraft` and
 * throws if blocking errors exist. Warnings (e.g. MIXED_ASSETS) do not
 * block building — they are surfaced via the summary for review.
 *
 * @example
 * const draft = new DraftBuilder("May payroll")
 *   .add({ recipientId: "GABC...", amount: "1000", asset: "native" })
 *   .add({ recipientId: "GDEF...", amount: "1500", asset: "USDC" })
 *   .build(); // throws DraftValidationFailedError if invalid
 */
export class DraftBuilder {
  private entries: PayrollDraftEntry[] = [];
  private readonly createdAt: string;
  private label: string | undefined;

  /**
   * Initializes an empty builder, or resumes editing an existing draft
   * (e.g. one returned from `importDraft`).
   */
  constructor(initialDraft?: PayrollDraft, label?: string) {
    this.createdAt = initialDraft?.createdAt ?? new Date().toISOString();
    this.label = initialDraft?.label ?? label;
    if (initialDraft) {
      // Defensive copy to avoid shared references with caller.
      this.entries = initialDraft.entries.map((e) => ({ ...e }));
    }
  }

  /** Appends a single payment entry to the draft. */
  add(entry: PayrollDraftEntry): this {
    this.entries.push({ ...entry });
    return this;
  }

  /** Appends multiple payment entries to the draft. */
  addMany(entries: PayrollDraftEntry[]): this {
    for (const entry of entries) {
      this.add(entry);
    }
    return this;
  }

  /**
   * Replaces the entry at `index` with the provided values.
   * @throws RangeError when `index` is out of bounds.
   */
  update(index: number, entry: PayrollDraftEntry): this {
    this.assertIndex(index, "update");
    this.entries[index] = { ...entry };
    return this;
  }

  /**
   * Removes the entry at `index`.
   * @throws RangeError when `index` is out of bounds.
   */
  remove(index: number): this {
    this.assertIndex(index, "remove");
    this.entries.splice(index, 1);
    return this;
  }

  /** Removes all entries from the draft. The label and createdAt are preserved. */
  clear(): this {
    this.entries = [];
    return this;
  }

  /** Sets or replaces the human-readable label for this draft. */
  setLabel(label: string | undefined): this {
    this.label = label;
    return this;
  }

  /**
   * Inspects the draft and returns both blocking errors and non-blocking
   * warnings. Does not mutate the builder state.
   */
  validate(): DraftValidationReport {
    const errors: DraftValidationError[] = [];
    const warnings: DraftWarning[] = [];

    if (this.entries.length === 0) {
      errors.push({
        code: "EMPTY_DRAFT",
        message: "Draft must contain at least one payment entry",
        field: "entries",
      });
      return { errors, warnings };
    }

    const seenRecipients = new Map<string, number>();
    const distinctAssets = new Set<string>();

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      if (!entry.recipientId || entry.recipientId.trim() === "") {
        errors.push({
          code: "INVALID_RECIPIENT",
          message: "Recipient address is required",
          field: "recipientId",
          index: i,
        });
      } else {
        const firstIdx = seenRecipients.get(entry.recipientId);
        if (firstIdx !== undefined) {
          errors.push({
            code: "DUPLICATE_RECIPIENT",
            message: `Duplicate recipient at indices ${firstIdx} and ${i}`,
            field: "recipientId",
            index: i,
          });
        } else {
          seenRecipients.set(entry.recipientId, i);
        }
      }

      const rawAmount = entry.amount ?? "";
      let amountBig = 0n;
      try {
        amountBig = BigInt(rawAmount === "" ? "0" : rawAmount);
      } catch {
        // Defer to INVALID_AMOUNT below.
      }
      if (rawAmount.trim() === "" || amountBig <= 0n) {
        errors.push({
          code: "INVALID_AMOUNT",
          message: "Amount must be a positive numeric value",
          field: "amount",
          index: i,
        });
      }

      if (!entry.asset || entry.asset.trim() === "") {
        errors.push({
          code: "MISSING_ASSET",
          message: "Asset identifier is required",
          field: "asset",
          index: i,
        });
      } else {
        distinctAssets.add(entry.asset);
      }

      if (entry.note !== undefined && entry.note.trim() === "") {
        warnings.push({
          code: "EMPTY_NOTE",
          message: "Note is empty and will be omitted from the draft output",
          field: "note",
          index: i,
        });
      }
    }

    if (distinctAssets.size > 1) {
      const assetList = Array.from(distinctAssets).sort().join(", ");
      warnings.push({
        code: "MIXED_ASSETS",
        message: `Draft mixes ${distinctAssets.size} assets (${assetList}); review whether a single-asset batch is required.`,
        field: "asset",
      });
    }

    if (this.entries.length > LARGE_DRAFT_THRESHOLD) {
      warnings.push({
        code: "LARGE_DRAFT",
        message: `Draft has ${this.entries.length} entries; consider splitting into smaller batches for gas efficiency.`,
        field: "entries",
      });
    }

    return { errors, warnings };
  }

  /**
   * Convenience aggregate used by review UIs: returns totals, validation
   * errors, and warnings in one call. Mirrors `validate()` semantics — never
   * throws and never mutates state.
   */
  summary(): DraftSummary {
    const { errors, warnings } = this.validate();
    const totalsByAsset: Record<string, bigint> = {};
    const uniqueRecipients = new Set<string>();
    const assets: string[] = [];

    for (const entry of this.entries) {
      if (entry.asset) {
        if (totalsByAsset[entry.asset] === undefined) {
          totalsByAsset[entry.asset] = 0n;
          assets.push(entry.asset);
        }
        try {
          totalsByAsset[entry.asset] += BigInt(entry.amount ?? "0");
        } catch {
          // Already reported via validate(); skip accumulation for invalid entries.
        }
      }
      if (entry.recipientId) {
        uniqueRecipients.add(entry.recipientId);
      }
    }

    // Serialize bigint totals to decimal strings so the summary is
    // JSON-friendly for UIs persisting the review state.
    const totals: Record<string, string> = {};
    for (const [asset, total] of Object.entries(totalsByAsset)) {
      totals[asset] = total.toString();
    }

    return {
      entryCount: this.entries.length,
      uniqueRecipientCount: uniqueRecipients.size,
      totalsByAsset: totals,
      assets,
      errors,
      warnings,
      isValid: errors.length === 0,
    };
  }

  /**
   * Inspects the draft's lock readiness and operational lock status (#537).
   *
   * Evaluates whether the current draft contents can be safely locked,
   * checking for active recipient locks, draft validity, and authorizer rules.
   */
  inspectLock(
    options?: import("./draftLockInspection").DraftLockInspectionOptions
  ): import("./draftLockInspection").DraftLockInspectionResult {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { inspectDraftLock } = require("./draftLockInspection");
    return inspectDraftLock(this, options);
  }

  /**
   * Asserts that the draft can be safely locked, throwing DraftLockError if not (#537).
   */
  assertLockable(options?: import("./draftLockInspection").DraftLockInspectionOptions): this {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { assertDraftLockable } = require("./draftLockInspection");
    assertDraftLockable(this, options);
    return this;
  }

  /**
   * Returns an immutable `PayrollDraft` snapshot suitable for serialization
   * or handoff to the submission step.
   *
   * @throws {DraftValidationFailedError} when any blocking errors exist.
   */
  build(): PayrollDraft {
    const { errors } = this.validate();
    if (errors.length > 0) {
      throw new DraftValidationFailedError(errors);
    }

    // Strip empty optional notes; never expose empty-string serialization.
    const sanitizedEntries = this.entries.map((entry) => {
      const clone: PayrollDraftEntry = {
        recipientId: entry.recipientId,
        amount: entry.amount,
        asset: entry.asset,
      };
      if (entry.note && entry.note.trim() !== "") {
        clone.note = entry.note;
      }
      return clone;
    });

    return {
      version: 1,
      createdAt: this.createdAt,
      updatedAt: new Date().toISOString(),
      label: this.label,
      entries: sanitizedEntries,
    };
  }

  private assertIndex(index: number, op: string): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.entries.length) {
      throw new RangeError(
        `DraftBuilder.${op}() index ${index} is out of bounds (entries: ${this.entries.length}).`
      );
    }
  }
}
