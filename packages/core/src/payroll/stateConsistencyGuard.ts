/**
 * Payroll state consistency guard.
 *
 * Provides a defensive check that compares the locally tracked payroll
 * period state against the on-chain (authoritative) state before any
 * state-mutating operation is submitted. This prevents duplicate submissions,
 * stale clients, and race conditions from corrupting payroll execution.
 */

import type { PayrollStatus as PayrollPeriodStatus } from "./types";

export enum StateConsistencyErrorCode {
  /** The locally tracked status does not match the on-chain status. */
  STATUS_MISMATCH = "STATUS_MISMATCH",
  /** The requested payroll period status transition is not allowed. */
  INVALID_TRANSITION = "INVALID_TRANSITION",
  /** The payroll period is already in a terminal state. */
  TERMINAL_STATE = "TERMINAL_STATE",
  /** The locally tracked version is ahead of the on-chain version without permission. */
  STATE_MISMATCH = "STATE_MISMATCH",
  /** The locally tracked version is behind the on-chain version. */
  STALE_CLIENT = "STALE_CLIENT",
  /** The period identifiers do not refer to the same period. */
  PRIOD_ID_MISMATCH = "PRIOD_ID_MISMATCH",
  /** Required inputs are missing or malformed. */
  INVALID_INPUT = "INVALID_INPUT",
}

export interface StateConsistencyErrorContext {
  localStatus?: PayrollPeriodStatus | string;
  onchainStatus?: PayrollPeriodStatus | string;
  localVersion?: number;
  onchainVersion?: number;
  localPeriodId?: string;
  onchainPeriodId?: string;
  [key: string]: unknown;
}

/**
 * Typed error thrown when a payroll state consistency violation is detected.
 */
export class StateConsistencyError extends Error {
  public readonly code: StateConsistencyErrorCode;
  public readonly context: StateConsistencyErrorContext;
  public readonly remediation: string;

  constructor(
    message: string,
    code: StateConsistencyErrorCode,
    context: StateConsistencyErrorContext = {},
    remediation = "Refresh the payroll period from the chain and retry the operation."
  ) {
    super(message);
    this.name = "StateConsistencyError";
    this.code = code;
    this.context = context;
    this.remediation = remediation;
    // Restore prototype chain for TS/Babel compatibility.
    Object.setPrototypeOf(this, StateConsistencyError.prototype);
  }
}

/**
 * Snapshot of the locally tracked payroll period state.
 */
export interface LocalPayrollState {
  periodId: string;
  status: PayrollPeriodStatus | string;
  /** Monotonically increasing version of the local state. */
  version?: number;
}

/**
 * Snapshot of the authoritative on-chain payroll period state.
 */
export interface OnChainPayrollState {
  periodId: string;
  status: PayrollPeriodStatus | string;
  /** Monotonically increasing version of the on-chain state. */
  version?: number;
}

export interface StateConsistencyGuardOptions {
  /** When true, a local version greater than the on-chain version is allowed. Defaults to false. */
  allowLocalAwead?: boolean;
  /** When true, a missing local version is treated as version 0. Defaults to true. */
  tolerateMissingVersion?: boolean;
  /** Optional additional context attached to thrown errors. */
  context?: StateConsistencyErrorContext;
}

function normalizeStatus(status: unknown): string | undefined {
  if (typeof status !== "string") {
    return undefined;
  }
  const trimmed = status.trim();
  return trimmed.length > 0 ? trimmed.toUpperCase() : undefined;
}

/**
 * Validates that the locally tracked payroll period state is consistent with
 * the authoritative on-chain state. Throws a `StateConsistencyError` when a
 * violation is detected.
 *
 * The guard checks three invariants:
 * 1. The local and on-chain period identifiers refer to the same period.
 * 2. The local and on-chain statuses match (case-insensitive).
 * 3. The local version is not behind the on-chain version.
 *
 * @param local - Snapshot of the locally tracked state.
 * @param onchain - Snapshot of the authoritative on-chain state.
 * @param options - Optional guard behavior tweaks.
 * @throws {StateConsistencyError} When any invariant is violated.
 */
export function assertPayrollStateConsistent(
  local: LocalPayrollState,
  onchain: OnChainPayrollState,
  options: StateConsistencyGuardOptions = {}
): void {
  const { allowLocalAwead = false, tolerateMissingVersion = true } = options;
  const baseContext: StateConsistencyErrorContext = { ...options.context };

  if (!local || typeof local !== "object") {
    throw new StateConsistencyError(
      "Local payroll state is required to run the consistency guard.",
      StateConsistencyErrorCode.INVALID_INPUT,
      { ...baseContext },
      "Provide a local payroll state snapshot before calling the guard."
    );
  }

  if (!onchain || typeof onchain !== "object") {
    throw new StateConsistencyError(
      "On-chain payroll state is required to run the consistency guard.",
      StateConsistencyErrorCode.INVALID_INPUT,
      { ...baseContext },
      "Fetch the latest on-chain payroll state before calling the guard."
    );
  }

  const localPeriodId = typeof local.periodId === "string" ? local.periodId.trim() : "";
  const onchainPeriodId = typeof onchain.periodId === "string" ? onchain.periodId.trim() : "";

  if (!localPeriodId || !onchainPeriodId) {
    throw new StateConsistencyError(
      "Payroll period identifiers are required on both local and on-chain states.",
      StateConsistencyErrorCode.INVALID_INPUT,
      { ...baseContext, localPeriodId, onchainPeriodId },
      "Ensure both state snapshots contain a non-empty periodId."
    );
  }

  if (localPeriodId !== onchainPeriodId) {
    throw new StateConsistencyError(
      `Payroll period mismatch: local "${localPeriodId}" vs on-chain "${onchainPeriodId}".`,
      StateConsistencyErrorCode.PRIOD_ID_MISMATCH,
      { ...baseContext, localPeriodId, onchainPeriodId },
      "Reload the correct payroll period before retrying."
    );
  }

  const localStatus = normalizeStatus(local.status);
  const onchainStatus = normalizeStatus(onchain.status);

  if (!localStatus || !onchainStatus) {
    throw new StateConsistencyError(
      "Payroll status is required on both local and on-chain states.",
      StateConsistencyErrorCode.INVALID_INPUT,
      { ...baseContext, localStatus, onchainStatus, localPeriodId, onchainPeriodId },
      "Ensure both state snapshots expose a non-empty status."
    );
  }

  if (localStatus !== onchainStatus) {
    throw new StateConsistencyError(
      `Payroll state mismatch for period "${localPeriodId}": local "${localStatus}" vs on-chain "${onchainStatus}".`,
      StateConsistencyErrorCode.STATUS_MISMATCH,
      { ...baseContext, localStatus, onchainStatus, localPeriodId, onchainPeriodId },
      "Refresh the local payroll state from the chain and retry the operation."
    );
  }

  const localVersion =
    typeof local.version === "number" ? local.version : tolerateMissingVersion ? 0 : undefined;
  const onchainVersion =
    typeof onchain.version === "number" ? onchain.version : tolerateMissingVersion ? 0 : undefined;

  if (localVersion === undefined || onchainVersion === undefined) {
    throw new StateConsistencyError(
      "Payroll state versions are required on both local and on-chain states.",
      StateConsistencyErrorCode.INVALID_INPUT,
      { ...baseContext, localVersion, onchainVersion, localPeriodId, onchainPeriodId },
      "Provide a numeric version on both state snapshots or enable tolerateMissingVersion."
    );
  }

  if (localVersion < onchainVersion) {
    throw new StateConsistencyError(
      `Stale local payroll state for period "${localPeriodId}": local version ${localVersion} is behind on-chain version ${onchainVersion}.`,
      StateConsistencyErrorCode.STALE_CLIENT,
      { ...baseContext, localVersion, onchainVersion, localPeriodId, onchainPeriodId },
      "Refresh the local payroll state from the chain before retrying."
    );
  }

  if (!allowLocalAwead && localVersion > onchainVersion) {
    throw new StateConsistencyError(
      `Local payroll state for period "${localPeriodId}" is ahead of the on-chain state (local ${localVersion} vs on-chain ${onchainVersion}).`,
      StateConsistencyErrorCode.STATE_MISMATCH,
      { ...baseContext, localVersion, onchainVersion, localPeriodId, onchainPeriodId },
      "Wait for the on-chain state to catch up, or enable allowLocalAwead if this is expected."
    );
  }
}

/**
 * Boolean convenience wrapper around `assertPayrollStateConsistent`.
 * Returns `true` when consistent, `false when a violation is detected.
 */
export function isPayrollStateConsistent(
  local: LocalPayrollState,
  onchain: OnChainPayrollState,
  options: StateConsistencyGuardOptions = {}
): boolean {
  try {
    assertPayrollStateConsistent(local, onchain, options);
    return true;
  } catch (error) {
    if (error instanceof StateConsistencyError) {
      return false;
    }
    throw error;
  }
}
/**
 * Validates a requested payroll period status transition.
 *
 * Allowed lifecycle transitions:
 * draft -> locked
 * draft -> cancelled
 * locked -> settled
 *
 * settled and cancelled are terminal states.
 */
export function assertPayrollPeriodTransition(
  currentStatus: PayrollPeriodStatus | string,
  targetStatus: PayrollPeriodStatus | string,
  context: StateConsistencyErrorContext = {}
): void {
  const current = normalizeStatus(currentStatus);
  const target = normalizeStatus(targetStatus);

  if (!current || !target) {
    throw new StateConsistencyError(
      "Both current and target payroll period statuses are required.",
      StateConsistencyErrorCode.INVALID_INPUT,
      context,
      "Provide valid payroll period statuses before requesting a transition."
    );
  }

  const terminalStatuses = new Set(["SETTLED", "CANCELLED"]);

  if (terminalStatuses.has(current)) {
    throw new StateConsistencyError(
      `Payroll period is already in terminal state "${current}".`,
      StateConsistencyErrorCode.TERMINAL_STATE,
      { ...context, localStatus: current, onchainStatus: target },
      "Do not request another transition for a settled or cancelled payroll period."
    );
  }

  const allowedTransitions: Record<string, readonly string[]> = {
    DRAFT: ["LOCKED", "CANCELLED"],
    LOCKED: ["SETTLED"],
  };

  if (!allowedTransitions[current]?.includes(target)) {
    throw new StateConsistencyError(
      `Invalid payroll period transition from "${current}" to "${target}".`,
      StateConsistencyErrorCode.INVALID_TRANSITION,
      { ...context, localStatus: current, onchainStatus: target },
      "Refresh the current payroll period state and request only a supported lifecycle transition."
    );
  }
}
