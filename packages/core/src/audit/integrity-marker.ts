import { createHash, createHmac } from "crypto";

export interface AuditExportPayload {
  exportId: string;
  timestamp: string;
  payrollBatchId: string;
  records: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
}

export interface IntegrityMarkerResult {
  exportId: string;
  marker: string;
  algorithm: string;
  createdAt: string;
}

export class AuditIntegrityMarkerManager {
  private algorithm: string;

  constructor(algorithm: string = "sha256") {
    this.algorithm = algorithm;
  }

  public generateMarker(payload: AuditExportPayload, secretKey?: string): IntegrityMarkerResult {
    if (!payload || !payload.exportId) {
      throw new Error("Invalid audit export payload: missing exportId");
    }

    const canonicalString = JSON.stringify({
      exportId: payload.exportId,
      timestamp: payload.timestamp,
      payrollBatchId: payload.payrollBatchId,
      records: payload.records,
      metadata: payload.metadata || {},
    });

    let marker: string;
    if (secretKey) {
      marker = createHmac(this.algorithm, secretKey).update(canonicalString).digest("hex");
    } else {
      marker = createHash(this.algorithm).update(canonicalString).digest("hex");
    }

    return {
      exportId: payload.exportId,
      marker,
      algorithm: this.algorithm,
      createdAt: new Date().toISOString(),
    };
  }

  public verifyMarker(payload: AuditExportPayload, marker: string, secretKey?: string): boolean {
    try {
      const generated = this.generateMarker(payload, secretKey);
      return generated.marker === marker;
    } catch {
      return false;
    }
  }
}
