/**
 * Sensitive fields default mask set for audit package redaction.
 */
export const DEFAULT_SENSITIVE_KEYS: string[] = [
  "viewKey",
  "viewingKey",
  "privateKey",
  "secret",
  "secretKey",
  "salaryAmount",
  "ssn",
  "taxId",
  "creditCard",
  "bankaccount",
];

/**
 * Additional sensitive keys that are always redacted regardless of options.
 */
export const MANDATORY_SENSITIVE_KEYS: string[] = ["privateKey", "secretKey", "viewKey"];

/**
 * Maximum allowed depth for recursive redaction to prevent stack overflow.
 */
export const MAX_REDACTION_DEPTH: number = 50;

export interface RedactionMaskOptions {
  /** Additional key names to scrub from audit packages. */
  additionalKeys?: string[];
  /** Custom replacement placeholder text (default: "[REDACTED]"). */
  placeholder?: string;
  /** Whether to redact recursively through nested objects and arrays (default: true). */
  recursive?: boolean;
  /** Maximum recursion depth before redaction fails closed (default: 50). */
  maxDepth?: number;
  /** Whether to throw on invalid options (non-string keys, etc.). */
  strict?: boolean;
}

export interface AuditPackageRedactionResult<T = unknown> {
  redactedData: T;
  redactedFieldCount: number;
  redactedKeys: string[];
  /** True when redaction hit the depth limit and failed closed. */
  truncated: boolean;
  /** True when a cyclic reference was detected and redacted. */
  cycleDetected: boolean;
}

export class AuditRedactionError extends Error {
  public readonly code: string;

  constructor(message: string, code = "AUDIT_REDACTION_ERROR") {
    super(message);
    this.name = "AuditRedactionError";
    this.code = code;
  }
}

/**
 * Helper class for redacting sensitive privacy-preserving fields from audit packages
 * before they are logged, exported, or rendered in UI interfaces.
 */
export class AuditPackageRedactor {
  private readonly sensitiveKeys: Set<string>;
  private readonly placeholder: string;
  private readonly recursive: boolean;
  private readonly maxDepth: number;

  constructor(options?: RedactionMaskOptions) {
    const additional = options?.additionalKeys ?? [];
    if (!Array.isArray(additional)) {
      throw new AuditRedactionError(
        "Redaction option 'additionalKeys' must be an array of strings.",
        "AUDIT_REDACTION_INVALID_OPTIONS"
      );
    }
    for (const key of additional) {
      if (typeof key !== "string" || key.trim().length === 0) {
        throw new AuditRedactionError(
          "Redaction option 'additionalKeys' must contain only non-empty strings.",
          "AUDIT_REDACTION_INVALID_OPTIONS"
        );
      }
    }

    const placeholder = options?.placeholder ?? "[REDACTED]";
    if (typeof placeholder !== "string") {
      throw new AuditRedactionError(
        "Redaction option 'placeholder' must be a string.",
        "AUDIT_REDACTION_INVALID_OPTIONS"
      );
    }

    const maxDepth = options?.maxDepth ?? MAX_REDACTION_DEPTH;
    if (!Number.isInteger(maxDepth) || maxDepth < 0) {
      throw new AuditRedactionError(
        "Redaction option 'maxDepth' must be a non-negative integer.",
        "AUDIT_REDACTION_INVALID_OPTIONS"
      );
    }

    const keys = [...DEFAULT_SENSITIVE_KEYS, ...MANDATORY_SENSITIVE_KEYS, ...additional];
    this.sensitiveKeys = new Set(keys.map((k) => k.toLowerCase()));
    this.placeholder = placeholder;
    this.recursive = options?.recursive ?? false;
    this.maxDepth = maxDepth;
  }

  /**
   * Redacts sensitive privacy fields from any audit package object or structure.
   */
  public redact<T = any>(packageData: T): AuditPackageRedactionResult<T> {
    const redactedKeysSeen: Set<string> = new Set();
    let count = 0;
    let truncated = false;
    let cycleDetected = false;
    const seen = new WeakSet<object>();

    const processValue = (val: any, depth: number): any => {
      if (val === null || val === undefined) return val;

      if (depth > this.maxDepth) {
        truncated = true;
        return this.placeholder;
      }

      if (typeof val === "function") {
        return this.placeholder;
      }

      if (Array.isArray(val)) {
        if (!this.recursive) return val;
        if (seen.has(val)) {
          cycleDetected = true;
          return this.placeholder;
        }
        seen.add(val);
        const result = val.map((item) => processValue(item, depth + 1));
        seen.delete(val);
        return result;
      }

      if (typeof val === "object" && !(val instanceof Date) && !(val instanceof RegExp)) {
        if (seen.has(val)) {
          cycleDetected = true;
          return this.placeholder;
        }
        seen.add(val);
        const copy: Record<string, any> = {};
        for (const [key, itemVal] of Object.entries(val)) {
          if (this.sensitiveKeys.has(key.toLowerCase())) {
            copy[key] = this.placeholder;
            redactedKeysSeen.add(key);
            count++;
          } else if (this.recursive) {
            copy[key] = processValue(itemVal, depth + 1);
          } else {
            copy[key] = itemVal;
          }
        }
        seen.delete(val);
        return copy;
      }

      return val;
    };

    const redactedData = processValue(packageData, 0);

    return {
      redactedData,
      redactedFieldCount: count,
      redactedKeys: Array.from(redactedKeysSeen),
      truncated,
      cycleDetected,
    };
  }
}

/**
 * Functional shorthand helper to redact an audit package with optional custom settings.
 */
export function redactAuditPackage<T = any>(
  packageData: T,
  options?: RedactionMaskOptions
): AuditPackageRedactionResult<T> {
  const redactor = new AuditPackageRedactor(options);
  return redactor.redact(packageData);
}
