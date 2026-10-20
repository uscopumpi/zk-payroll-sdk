export interface AuditReceipt {
  receiptId: string;
  payrollId: string;
  timestamp: string;
  totalAmount: string;
  currency: string;
  recipientCount: number;
  viewKeyId?: string;
  complianceHash: string;
  redacted: boolean;
  metadata?: Record<string, unknown>;
}

export interface AuditReceiptSerializeOptions {
  redactPII?: boolean;
  pretty?: boolean;
  /** Maximum allowed serialized size in bytes. Defaults to 1 MiB. */
  maxSizeBytes?: number;
  /** Maximum allowed retention age in days. Defaults to 2555. */
  maxAgeDays?: number;
  /** Reference time for age validation. Defaults to now. */
  now?: Date | string | number;
}

export const DEFAULT_MAX_SIZE_BYTES = 1024 * 1024;
export const DEFAULT_MAX_AGE_DAYS = 2555;

/**
 * Validate that an unknown object conforms to the AuditReceipt interface shape.
 */
export function validateAuditReceiptShape(data: unknown): data is AuditReceipt {
  if (typeof data !== "object" || data === null) {
    return false;
  }

  const obj = data as Record<string, unknown>;

  return (
    typeof obj.receiptId === "string" &&
    typeof obj.payrollId === "string" &&
    typeof obj.timestamp === "string" &&
    typeof obj.totalAmount === "string" &&
    typeof obj.currency === "string" &&
    typeof obj.recipientCount === "number" &&
    typeof obj.complianceHash === "string" &&
    typeof obj.redacted === "boolean"
  );
}

function resolveNowValue(now?: Date | string | number): number {
  if (now === undefined) {
    return Date.now();
  }
  if (now instanceof Date) {
    return now.getTime();
  }
  if (typeof now === "number") {
    return now;
  }
  const parsed = Date.parse(now);
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid 'now' reference time provided: ${now}`);
  }
  return parsed;
}

/**
 * Enforce retention safeguards: reject receipts that are too old or too large.
 * Throws actionable errors so integrators can adjust retention policy or payload.
 */
export function enforceRetentionSafeguards(
  receipt: AuditReceipt,
  serialized: string,
  options: AuditReceiptSerializeOptions = {}
): void {
  const maxSizeBytes = options.maxSizeBytes ?? DEFAULT_MAX_SIZE_BYTES;
  if (!Number.isFinite(maxSizeBytes) || maxSizeBytes <= 0) {
    throw new Error(`Invalid maxSizeBytes option: ${maxSizeBytes}`);
  }

  const maxAgeDays = options.maxAgeDays ?? DEFAULT_MAX_AGE_DAYS;
  if (!Number.isFinite(maxAgeDays) || maxAgeDays <= 0) {
    throw new Error(`Invalid maxAgeDays option: ${maxAgeDays}`);
  }

  const timestampMs = Date.parse(receipt.timestamp);
  if (Number.isNaN(timestampMs)) {
    throw new Error(
      `AuditReceipt ${receipt.receiptId} has an invalid timestamp '${receipt.timestamp}'; expected an ISO 8601 date string`
    );
  }

  const nowMs = resolveNowValue(options.now);
  const ageMs = nowMs - timestampMs;
  const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;

  if (ageMs > maxAgeMs) {
    const ageDays = Math.floor(ageMs / (24 * 60 * 60 * 1000));
    throw new Error(
      `AuditReceipt ${receipt.receiptId} exceeds retention window: age ${ageDays} days > max ${maxAgeDays} days`
    );
  }

  const sizeBytes = Buffer.byteLength(serialized, "utf-8");
  if (sizeBytes > maxSizeBytes) {
    throw new Error(
      `AuditReceipt ${receipt.receiptId} exceeds max serialized size: ${sizeBytes} bytes > max ${maxSizeBytes} bytes`
    );
  }
}

/**
 * Serialize an AuditReceipt into a canonical JSON string for audit/compliance storage.
 */
export function serializeAuditReceipt(
  receipt: AuditReceipt,
  options: AuditReceiptSerializeOptions = {}
): string {
  if (!validateAuditReceiptShape(receipt)) {
    throw new Error("Invalid AuditReceipt shape provided for serialization");
  }

  const copy: AuditReceipt = { ...receipt };

  if (options.redactPII) {
    copy.redacted = true;
    if (copy.metadata) {
      const sanitizedMeta: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(copy.metadata)) {
        if (!/name|email|ssn|address|pii/i.test(key)) {
          sanitizedMeta[key] = value;
        } else {
          sanitizedMeta[key] = "[REDACTED]";
        }
      }
      copy.metadata = sanitizedMeta;
    }
  }

  const serialized = options.pretty ? JSON.stringify(copy, null, 2) : JSON.stringify(copy);

  enforceRetentionSafeguards(copy, serialized, options);

  return serialized;
}

/**
 * Deserialize a JSON string into a validated AuditReceipt.
 */
export function deserializeAuditReceipt(
  serialized: string,
  options: AuditReceiptSerializeOptions = {}
): AuditReceipt {
  try {
    const parsed = JSON.parse(serialized);
    if (!validateAuditReceiptShape(parsed)) {
      throw new Error("Parsed JSON does not match required AuditReceipt schema");
    }
    enforceRetentionSafeguards(parsed, serialized, options);
    return parsed;
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes("AuditReceipt schema")) {
      throw err;
    }
    if (err instanceof Error && err.message.startsWith("AuditReceipt ")) {
      throw err;
    }
    throw new Error(`Failed to deserialize AuditReceipt: ${(err as Error).message}`);
  }
}
