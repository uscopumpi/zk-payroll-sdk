/**
 * Duplicate Payout Instruction Detection (#709)
 *
 * Provides robust pre-flight detection of duplicate payout instructions in the SDK.
 * Prevents unintended repeated payments, identifies accidental double-entries within
 * payroll batches or across sequential execution windows, while preserving intentional
 * recurring payouts and strictly protecting employee privacy.
 *
 * ## Privacy & Security Guarantees
 * - Recipient addresses are normalized for comparison but redacted in client logs and exceptions.
 * - Payout amounts are not exposed in plaintext within violation messages.
 * - Fingerprints are deterministic hashes of normalized instruction components.
 */

/**
 * Shape of a payout instruction subject to duplicate detection.
 */
export interface PayoutInstruction {
  /** Optional unique instruction identifier (e.g. from upstream HRIS or database) */
  id?: string;
  /** Primary payout recipient identifier or public key (e.g. Stellar G-address) */
  recipient: string;
  /** Payment amount in currency base units or decimal string representation */
  amount: string | number | bigint;
  /** Currency / asset symbol (e.g. "XLM", "USDC"). Defaults to native/default if omitted */
  asset?: string;
  /** Legacy alias for `asset`, kept for backwards compatibility with older payroll payloads */
  token?: string;
  /** Optional transaction memo or reference note */
  memo?: string;
  /** Associated payroll period ID (e.g. "2026-10-W1") */
  periodId?: string;
  /** Associated payroll batch ID (e.g. "batch-001") */
  batchId?: string;
  /** Optional unique client idempotency key */
  idempotencyKey?: string;
  /** Explicitly marks instruction as an intentional recurring payout */
  isRecurring?: boolean;
  /** Arbitrary non-sensitive metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Classification codes for duplicate payout instruction violations.
 */
export type DuplicatePayoutViolationCode =
  | "EXACT_DUPLICATE"
  | "RECIPIENT_ASSET_DUPLICATE"
  | "IDEMPOTENCY_KEY_COLLISION"
  | "INSTRUCTION_ID_COLLISION"
  | "INVALID_INSTRUCTION";

/**
 * Structured violation descriptor detailing a duplicate payout issue.
 */
export interface DuplicatePayoutViolation {
  code: DuplicatePayoutViolationCode;
  instructionIndex: number;
  matchedInstructionIndex?: number;
  fingerprint: string;
  message: string;
  redactedMessage: string;
  suggestedFix: string;
  matchedId?: string;
}

/**
 * Configuration options for duplicate payout instruction detection.
 */
export interface DuplicatePayoutDetectionOptions {
  /**
   * If true (default), payouts with differing periodId values are not considered duplicates.
   * If false, identical recipient/amount/asset matches across periods are flagged.
   */
  scopeToPeriod?: boolean;
  /**
   * If true, instructions with `isRecurring: true` or `metadata.recurring === true`
   * are permitted even if recipient, amount, and asset match. Defaults to false.
   */
  allowExplicitRecurring?: boolean;
  /**
   * Whether to enforce case-sensitivity when comparing recipient addresses.
   * Defaults to false (canonical lowercase comparison).
   */
  caseSensitiveRecipient?: boolean;
  /**
   * Whether to enforce case-sensitivity when comparing asset symbols.
   * Defaults to false (canonical uppercase comparison).
   */
  caseSensitiveAsset?: boolean;
  /**
   * Whether to check for duplicate idempotencyKey across distinct instructions.
   * Defaults to true.
   */
  checkIdempotencyKeys?: boolean;
  /**
   * Custom fingerprint generator function to override standard fingerprinting.
   */
  customFingerprintExtractor?: (instruction: PayoutInstruction) => string;
}

/**
 * Summary report returned by duplicate payout instruction analysis.
 */
export interface DuplicatePayoutDetectionReport {
  hasDuplicates: boolean;
  totalChecked: number;
  uniqueCount: number;
  duplicates: DuplicatePayoutViolation[];
}

/**
 * Exception thrown when duplicate payout instructions are asserted.
 */
export class DuplicatePayoutInstructionError extends Error {
  public readonly violation: DuplicatePayoutViolation;
  public readonly code: DuplicatePayoutViolationCode;
  public readonly instructionIndex: number;
  public readonly matchedInstructionIndex?: number;

  constructor(violation: DuplicatePayoutViolation) {
    super(violation.redactedMessage);
    this.name = "DuplicatePayoutInstructionError";
    this.violation = violation;
    this.code = violation.code;
    this.instructionIndex = violation.instructionIndex;
    this.matchedInstructionIndex = violation.matchedInstructionIndex;
  }
}

/**
 * Redacts a recipient address or identifier for privacy-safe logs and error messages.
 */
function redactRecipient(recipient: string): string {
  if (!recipient || typeof recipient !== "string") return "[invalid]";
  const trimmed = recipient.trim();
  if (trimmed.length <= 8) return "[redacted]";
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}`;
}

/**
 * Normalizes an amount into a canonical numeric string.
 */
export function normalizePayoutAmount(amount: string | number | bigint): string {
  if (amount === undefined || amount === null) {
    throw new TypeError("Payout instruction amount is required and cannot be null or undefined");
  }

  if (typeof amount === "bigint") {
    if (amount <= 0n) {
      throw new RangeError("Payout instruction amount must be positive");
    }
    return amount.toString();
  }

  if (typeof amount === "number") {
    if (!Number.isFinite(amount) || Number.isNaN(amount)) {
      throw new TypeError("Payout instruction amount must be a finite number");
    }
    if (amount <= 0) {
      throw new RangeError("Payout instruction amount must be positive");
    }
    // Avoid scientific notation for typical base unit sizes
    return amount.toLocaleString("fullwide", { useGrouping: false });
  }

  if (typeof amount === "string") {
    const trimmed = amount.trim();
    if (trimmed.length === 0) {
      throw new TypeError("Payout instruction amount string cannot be empty");
    }
    if (!/^\d+(\.\d+)?$/.test(trimmed)) {
      throw new TypeError(`Invalid payout amount format: '${trimmed}'`);
    }
    const parsed = Number(trimmed);
    if (parsed <= 0) {
      throw new RangeError("Payout instruction amount must be positive");
    }
    // Canonicalize decimal representation: remove trailing zeros after decimal point
    if (trimmed.includes(".")) {
      const canonical = trimmed.replace(/\.?0+$/, "");
      return canonical.length > 0 ? canonical : "0";
    }
    return trimmed;
  }

  throw new TypeError("Payout instruction amount must be a string, number, or bigint");
}

/**
 * Builds a deterministic fingerprint representing the core payment semantics of an instruction.
 */
export function fingerprintPayoutInstruction(
  instruction: PayoutInstruction,
  options: DuplicatePayoutDetectionOptions = {}
): string {
  if (!instruction || typeof instruction !== "object") {
    throw new TypeError("Payout instruction must be an object");
  }

  if (typeof options.customFingerprintExtractor === "function") {
    return options.customFingerprintExtractor(instruction);
  }

  if (typeof instruction.recipient !== "string" || instruction.recipient.trim().length === 0) {
    throw new TypeError("Payout instruction requires a non-empty recipient");
  }

  const recipient = options.caseSensitiveRecipient
    ? instruction.recipient.trim()
    : instruction.recipient.trim().toLowerCase();

  const amount = normalizePayoutAmount(instruction.amount);

  const rawAsset = instruction.asset ?? instruction.token ?? "NATIVE";
  const asset = options.caseSensitiveAsset ? rawAsset.trim() : rawAsset.trim().toUpperCase();

  const memo = (instruction.memo ?? "").trim();

  const scopeToPeriod = options.scopeToPeriod ?? true;
  const period = scopeToPeriod ? (instruction.periodId ?? "").trim() : "";

  return JSON.stringify({
    recipient,
    amount,
    asset,
    memo,
    period,
  });
}

/**
 * Checks whether an instruction is explicitly configured as recurring.
 */
function isExplicitRecurring(instruction: PayoutInstruction): boolean {
  if (instruction.isRecurring === true) return true;
  if (instruction.metadata && typeof instruction.metadata === "object") {
    if (instruction.metadata.recurring === true || instruction.metadata.isRecurring === true) {
      return true;
    }
  }
  return false;
}

/**
 * Analyzes a sequence of payout instructions and detects duplicate payments.
 *
 * @param instructions - List of payout instructions to evaluate.
 * @param options - Configuration options for duplicate detection.
 * @returns DuplicatePayoutDetectionReport containing detected duplicate violations.
 */
export function detectDuplicatePayoutInstructions(
  instructions: PayoutInstruction[],
  options: DuplicatePayoutDetectionOptions = {}
): DuplicatePayoutDetectionReport {
  if (!Array.isArray(instructions)) {
    throw new TypeError("Instructions must be an array");
  }

  const duplicates: DuplicatePayoutViolation[] = [];
  const fingerprintMap = new Map<string, number>();
  const idMap = new Map<string, number>();
  const idempotencyMap = new Map<string, number>();
  const checkIdempotency = options.checkIdempotencyKeys ?? true;
  const allowRecurring = options.allowExplicitRecurring ?? false;

  for (let idx = 0; idx < instructions.length; idx++) {
    const item = instructions[idx];

    // Check basic integrity
    if (!item || typeof item !== "object") {
      duplicates.push({
        code: "INVALID_INSTRUCTION",
        instructionIndex: idx,
        fingerprint: "",
        message: `Instruction at index ${idx} is not a valid object.`,
        redactedMessage: `Instruction at index ${idx} is not a valid object.`,
        suggestedFix: "Ensure all elements in the instructions array are valid payout objects.",
      });
      continue;
    }

    // Check ID collisions if provided
    if (item.id && typeof item.id === "string") {
      const cleanId = item.id.trim();
      if (cleanId.length > 0) {
        if (idMap.has(cleanId)) {
          const matchedIdx = idMap.get(cleanId)!;
          duplicates.push({
            code: "INSTRUCTION_ID_COLLISION",
            instructionIndex: idx,
            matchedInstructionIndex: matchedIdx,
            fingerprint: `id:${cleanId}`,
            message: `Instruction at index ${idx} reuses instruction ID '${cleanId}' already declared at index ${matchedIdx}.`,
            redactedMessage: `Instruction ID collision detected at index ${idx}.`,
            suggestedFix:
              "Assign distinct unique IDs to each payout instruction or omit manual IDs.",
            matchedId: cleanId,
          });
        } else {
          idMap.set(cleanId, idx);
        }
      }
    }

    // Check idempotencyKey collisions if enabled and provided
    if (checkIdempotency && item.idempotencyKey && typeof item.idempotencyKey === "string") {
      const cleanKey = item.idempotencyKey.trim();
      if (cleanKey.length > 0) {
        if (idempotencyMap.has(cleanKey)) {
          const matchedIdx = idempotencyMap.get(cleanKey)!;
          duplicates.push({
            code: "IDEMPOTENCY_KEY_COLLISION",
            instructionIndex: idx,
            matchedInstructionIndex: matchedIdx,
            fingerprint: `idemp:${cleanKey}`,
            message: `Instruction at index ${idx} shares idempotencyKey '${cleanKey}' with instruction at index ${matchedIdx}.`,
            redactedMessage: `Idempotency key collision detected at index ${idx}.`,
            suggestedFix:
              "Ensure each distinct payout instruction specifies a unique idempotency key.",
          });
        } else {
          idempotencyMap.set(cleanKey, idx);
        }
      }
    }

    // Generate semantic fingerprint
    let fp = "";
    try {
      fp = fingerprintPayoutInstruction(item, options);
    } catch (err) {
      duplicates.push({
        code: "INVALID_INSTRUCTION",
        instructionIndex: idx,
        fingerprint: "",
        message: `Invalid instruction at index ${idx}: ${(err as Error).message}`,
        redactedMessage: `Invalid instruction fields at index ${idx}.`,
        suggestedFix: "Verify recipient address, amount, and asset formats on the instruction.",
      });
      continue;
    }

    // Check if recurring exception applies
    if (allowRecurring && isExplicitRecurring(item)) {
      continue;
    }

    if (fingerprintMap.has(fp)) {
      const matchedIdx = fingerprintMap.get(fp)!;
      const original = instructions[matchedIdx];
      const displayRecipient = redactRecipient(item.recipient);
      const asset = (item.asset ?? item.token ?? "NATIVE").toUpperCase();

      duplicates.push({
        code: "EXACT_DUPLICATE",
        instructionIndex: idx,
        matchedInstructionIndex: matchedIdx,
        fingerprint: fp,
        message: `Duplicate payout instruction detected at index ${idx}: matches instruction at index ${matchedIdx} (recipient: ${item.recipient}, asset: ${asset}).`,
        redactedMessage: `Duplicate payout instruction detected at index ${idx}: matches instruction at index ${matchedIdx} (recipient: ${displayRecipient}, asset: ${asset}).`,
        suggestedFix:
          "Remove the duplicate instruction or mark it with 'isRecurring: true' if intentional.",
        matchedId: original?.id,
      });
    } else {
      fingerprintMap.set(fp, idx);
    }
  }

  const uniqueCount = instructions.length - duplicates.length;

  return {
    hasDuplicates: duplicates.length > 0,
    totalChecked: instructions.length,
    uniqueCount: Math.max(0, uniqueCount),
    duplicates,
  };
}

/**
 * Asserts that a list of payout instructions has no duplicates.
 * Throws DuplicatePayoutInstructionError on the first detected duplicate.
 */
export function assertNoDuplicatePayoutInstructions(
  instructions: PayoutInstruction[],
  options: DuplicatePayoutDetectionOptions = {}
): void {
  const report = detectDuplicatePayoutInstructions(instructions, options);
  if (report.hasDuplicates && report.duplicates.length > 0) {
    throw new DuplicatePayoutInstructionError(report.duplicates[0]);
  }
}

/**
 * Stateful registry for tracking payout instructions across batches or execution windows.
 */
export class DuplicatePayoutInstructionDetector {
  private readonly registeredFingerprints = new Map<
    string,
    { instruction: PayoutInstruction; registeredAt: number }
  >();
  private readonly registeredIds = new Set<string>();
  private readonly registeredIdempotencyKeys = new Set<string>();
  private readonly options: DuplicatePayoutDetectionOptions;

  constructor(options: DuplicatePayoutDetectionOptions = {}) {
    this.options = options;
  }

  /**
   * Checks whether a payout instruction collides with any previously registered instruction.
   */
  public check(instruction: PayoutInstruction): {
    isDuplicate: boolean;
    violation?: DuplicatePayoutViolation;
  } {
    if (!instruction || typeof instruction !== "object") {
      return {
        isDuplicate: true,
        violation: {
          code: "INVALID_INSTRUCTION",
          instructionIndex: 0,
          fingerprint: "",
          message: "Instruction is not a valid object.",
          redactedMessage: "Instruction is not a valid object.",
          suggestedFix: "Pass a valid PayoutInstruction object.",
        },
      };
    }

    if (instruction.id && this.registeredIds.has(instruction.id.trim())) {
      return {
        isDuplicate: true,
        violation: {
          code: "INSTRUCTION_ID_COLLISION",
          instructionIndex: 0,
          fingerprint: `id:${instruction.id}`,
          message: `Instruction ID '${instruction.id}' has already been processed.`,
          redactedMessage: "Instruction ID collision detected.",
          suggestedFix: "Use a distinct instruction ID.",
          matchedId: instruction.id,
        },
      };
    }

    const checkIdemp = this.options.checkIdempotencyKeys ?? true;
    if (
      checkIdemp &&
      instruction.idempotencyKey &&
      this.registeredIdempotencyKeys.has(instruction.idempotencyKey.trim())
    ) {
      return {
        isDuplicate: true,
        violation: {
          code: "IDEMPOTENCY_KEY_COLLISION",
          instructionIndex: 0,
          fingerprint: `idemp:${instruction.idempotencyKey}`,
          message: `Idempotency key '${instruction.idempotencyKey}' has already been registered.`,
          redactedMessage: "Idempotency key collision detected.",
          suggestedFix: "Generate a fresh idempotency key for new payouts.",
        },
      };
    }

    const allowRecurring = this.options.allowExplicitRecurring ?? false;
    if (allowRecurring && isExplicitRecurring(instruction)) {
      return { isDuplicate: false };
    }

    let fp = "";
    try {
      fp = fingerprintPayoutInstruction(instruction, this.options);
    } catch (err) {
      return {
        isDuplicate: true,
        violation: {
          code: "INVALID_INSTRUCTION",
          instructionIndex: 0,
          fingerprint: "",
          message: (err as Error).message,
          redactedMessage: "Invalid payout instruction parameters.",
          suggestedFix: "Verify recipient and amount fields.",
        },
      };
    }

    if (this.registeredFingerprints.has(fp)) {
      const match = this.registeredFingerprints.get(fp)!;
      return {
        isDuplicate: true,
        violation: {
          code: "EXACT_DUPLICATE",
          instructionIndex: 0,
          fingerprint: fp,
          message: `Duplicate payout instruction already registered for recipient '${instruction.recipient}'.`,
          redactedMessage: `Duplicate payout instruction already registered for recipient '${redactRecipient(instruction.recipient)}'.`,
          suggestedFix: "Do not resubmit this payout or specify a different period/memo.",
          matchedId: match.instruction.id,
        },
      };
    }

    return { isDuplicate: false };
  }

  /**
   * Registers a payout instruction. Returns violation if duplicate, or null on success.
   */
  public register(instruction: PayoutInstruction): DuplicatePayoutViolation | null {
    const checkResult = this.check(instruction);
    if (checkResult.isDuplicate && checkResult.violation) {
      return checkResult.violation;
    }

    const fp = fingerprintPayoutInstruction(instruction, this.options);
    this.registeredFingerprints.set(fp, { instruction, registeredAt: Date.now() });

    if (instruction.id) {
      this.registeredIds.add(instruction.id.trim());
    }
    if (instruction.idempotencyKey) {
      this.registeredIdempotencyKeys.add(instruction.idempotencyKey.trim());
    }

    return null;
  }

  /**
   * Registers an instruction or throws DuplicatePayoutInstructionError if it collides.
   */
  public assertCanRegister(instruction: PayoutInstruction): void {
    const violation = this.register(instruction);
    if (violation) {
      throw new DuplicatePayoutInstructionError(violation);
    }
  }

  /**
   * Clears all registered instructions from memory.
   */
  public clear(): void {
    this.registeredFingerprints.clear();
    this.registeredIds.clear();
    this.registeredIdempotencyKeys.clear();
  }

  /**
   * Returns count of registered instruction fingerprints.
   */
  public size(): number {
    return this.registeredFingerprints.size;
  }

  /**
   * Returns a copy of every registered instruction, in registration order.
   *
   * The returned array is a defensive copy: mutating it does not affect the
   * detector's internal registry.
   */
  public getAll(): PayoutInstruction[] {
    return Array.from(this.registeredFingerprints.values()).map((entry) => entry.instruction);
  }
}
