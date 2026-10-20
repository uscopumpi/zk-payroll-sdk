import { AuditIntegrityMarkerManager, AuditExportPayload } from "../../src/audit/integrity-marker";

describe("AuditIntegrityMarkerManager (#604)", () => {
  let manager: AuditIntegrityMarkerManager;
  const samplePayload: AuditExportPayload = {
    exportId: "exp-1001",
    timestamp: "2026-10-16T12:00:00Z",
    payrollBatchId: "batch-001",
    records: [{ recipient: "0x123", amount: "500" }],
  };

  beforeEach(() => {
    manager = new AuditIntegrityMarkerManager("sha256");
  });

  it("successfully generates and verifies an audit export integrity marker", () => {
    const result = manager.generateMarker(samplePayload);
    expect(result.exportId).toBe("exp-1001");
    expect(result.marker).toBeDefined();
    expect(result.marker.length).toBe(64); // SHA-256 hex length

    const isValid = manager.verifyMarker(samplePayload, result.marker);
    expect(isValid).toBe(true);
  });

  it("fails verification when payload is tampered with", () => {
    const result = manager.generateMarker(samplePayload);

    const tamperedPayload: AuditExportPayload = {
      ...samplePayload,
      records: [{ recipient: "0x123", amount: "9999" }],
    };

    const isValid = manager.verifyMarker(tamperedPayload, result.marker);
    expect(isValid).toBe(false);
  });

  it("supports HMAC-based signatures with a secret key", () => {
    const secret = "super-secret-audit-key";
    const hmacManager = new AuditIntegrityMarkerManager("sha256");

    const result = hmacManager.generateMarker(samplePayload, secret);
    expect(hmacManager.verifyMarker(samplePayload, result.marker, secret)).toBe(true);
    expect(hmacManager.verifyMarker(samplePayload, result.marker, "wrong-secret")).toBe(false);
  });

  it("throws error on invalid payload", () => {
    expect(() => manager.generateMarker({} as AuditExportPayload)).toThrow(
      "Invalid audit export payload"
    );
  });
});
