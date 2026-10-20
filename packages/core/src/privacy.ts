import { ValidationError } from "./core/errors";
import { sha256Digest } from "./crypto/hashUtils";

/** A note hash reference safe to attach to a contract payload. */
export interface NoteHashReference {
  noteHash: string;
  source: "generated" | "provided";
}

const NOTE_HASH_PATTERN = /^[0-9a-f]{64}$/;

/** True when `value` is a 64-char lowercase hex SHA-256 digest. */
export function isValidNoteHash(value: unknown): value is string {
  return typeof value === "string" && NOTE_HASH_PATTERN.test(value);
}

/**
 * Build a note hash reference from note text or an existing hash.
 * Pass exactly one of `note` / `noteHash`. Raw note text is never returned.
 */
export async function buildNoteHash(input: {
  note?: string;
  noteHash?: string;
}): Promise<NoteHashReference> {
  if (input.noteHash !== undefined) {
    if (!isValidNoteHash(input.noteHash)) {
      throw new ValidationError("Invalid note hash", "noteHash", "INVALID_NOTE_HASH");
    }
    return { noteHash: input.noteHash, source: "provided" };
  }

  if (!input.note || input.note.trim() === "") {
    throw new ValidationError(
      "Provide `note` text or an existing `noteHash`",
      "note",
      "INVALID_NOTE_HASH_INPUT"
    );
  }

  const digest = await sha256Digest(new TextEncoder().encode(input.note));
  return { noteHash: digest, source: "generated" };
}

/** Attach a note hash to a payload, stripping any raw `note` text. */
export function attachNoteHash<T extends Record<string, unknown>>(
  payload: T,
  reference: NoteHashReference
): Omit<T, "note"> & { noteHash: string } {
  if (!isValidNoteHash(reference.noteHash)) {
    throw new ValidationError("Invalid note hash", "noteHash", "INVALID_NOTE_HASH");
  }
  const { note: _note, ...rest } = payload as T & { note?: unknown };
  return { ...(rest as Omit<T, "note">), noteHash: reference.noteHash };
}

// ── Note hash verification (#614) ───────────────────────────────────────────

/** Reason a note hash verification attempt failed. */
export type NoteHashVerificationFailureCode =
  "MISSING_NOTE_AND_HASH" | "INVALID_EXPECTED_NOTE_HASH" | "NOTE_HASH_MISMATCH";

/** Structured failure descriptor for a failed verification attempt. */
export interface NoteHashVerificationFailure {
  code: NoteHashVerificationFailureCode;
  /** Human-readable, privacy-safe message. Never echoes raw note text. */
  message: string;
}

/** Result of verifying payroll note text against an expected note hash. */
export interface NoteHashVerificationResult {
  verified: boolean;
  /** Present only when `verified` is false. */
  failure?: NoteHashVerificationFailure;
}

/** Inputs for {@link verifyNoteHash}. Pass both `note` and `noteHash`. */
export interface NoteHashVerificationInput {
  /** Raw note text to recompute the digest from. */
  note?: string;
  /** Expected 64-char lowercase hex SHA-256 digest. */
  noteHash?: string;
}

/**
 * Verify payroll note text against an expected note hash.
 *
 * Recomputes the SHA-256 digest of `note` and compares it to the expected
 * `noteHash` using a constant-time comparison over the hex digests. The
 * comparison never short-circuits on the first differing character.
 *
 * Never throws, never returns or logs raw note text. Use the structured
 * `failure` to surface actionable errors to integrators:
 * - `MISSING_NOTE_AND_HASH`: both `note` and `noteHash` are required.
 * - `INVALID_EXPECTED_NOTE_HASH`: the expected hash is not a 64-char
 *   lowercase hex SHA-256 digest.
 * - `NOTE_HASH_MISMATCH`: the note text does not hash to the expected value.
 *
 * @example
 * ```typescript
 * const result = await verifyNoteHash({ note, noteHash: payload.noteHash });
 * if (!result.verified) {
 *   console.error(result.failure.code, result.failure.message); // safe to log
 * }
 * ```
 */
export async function verifyNoteHash(
  input: NoteHashVerificationInput
): Promise<NoteHashVerificationResult> {
  const { note, noteHash } = input;

  if (typeof note !== "string" || typeof noteHash !== "string") {
    return {
      verified: false,
      failure: {
        code: "MISSING_NOTE_AND_HASH",
        message: "Provide `note` text and an expected `noteHash` to verify against.",
      },
    };
  }

  if (!isValidNoteHash(noteHash)) {
    return {
      verified: false,
      failure: {
        code: "INVALID_EXPECTED_NOTE_HASH",
        message: "The expected `noteHash` must be a 64-character lowercase hex SHA-256 digest.",
      },
    };
  }

  const digest = await sha256Digest(new TextEncoder().encode(note));
  if (!secureCompareHex(digest, noteHash)) {
    return {
      verified: false,
      failure: {
        code: "NOTE_HASH_MISMATCH",
        message: "The provided note does not match the expected note hash.",
      },
    };
  }

  return { verified: true };
}

/**
 * Constant-time equality check for hex digests of equal length.
 * Compares every character regardless of earlier mismatches, so comparison
 * time does not leak which characters differ.
 */
export function secureCompareHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
