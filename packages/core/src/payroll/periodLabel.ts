/**
 * Payroll Period Label Formatter (#410).
 *
 * Helpers for formatting payroll period labels for UI display and
 * event summaries. Keeps dashboard screens consistent and avoids
 * repeated date or period logic.
 *
 * Timezone boundary handling: payroll cycles are defined in UTC, but
 * operators and contributors may view labels from any local timezone.
 * This module exposes timezone-aware helpers that resolve the correct
 * payroll period for a given instant and locale without shifting the
 * canonical UTC period boundaries.
 */

import {
  formatPeriodLabel,
  formatPeriodCompact,
  formatTimestampToPeriod,
  getPreviousPeriod,
  getNextPeriod,
} from "../utils/date";

/**
 * The canonical timezone in which payroll period boundaries are defined.
 * Payroll cycles always start and end at UTC midnight on the first
 * day of the month.
 */
export const PAYROLL_TIMEZONE = "UTC" as const;

/**
 * Regular expression matching a valid "YYYY-MM" payroll period identifier.
 */
const PERIOD_PATTERN = /^(\d{4})-(\d{2})$/;

/**
 * Error thrown when a payroll period identifier is malformed or out of
 * range. Exposed so integrators can distinguish invalid input from
 * other failures.
 */
export class InvalidPeriodError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPeriodError";
  }
}

/**
 * Parses a "YYYY-MM" period identifier into its year and month
 * components. Throws an InvalidPeriodError with an actionable message
 * when the input is not a valid calendar month.
 *
 * @param period - Period identifier in "YYYY-MM" format
 * @returns Parsed year and month (1-indexed)
 */
export function parsePeriod(period: string): { year: number; month: number } {
  if (typeof period !== "string") {
    throw new InvalidPeriodError(
      `Payroll period must be a string in "YYYY-MM" format, received ${typeof period}`
    );
  }

  const match = PERIOD_PATTERN.exec(period);
  if (!match) {
    throw new InvalidPeriodError(
      `Invalid payroll period "${period}". Expected "YYYY-MM" (e.g. "2024-01").`
    );
  }

  const year = Number(match[1]);
  const month = Number(match[2]);

  if (month < 1 || month > 12) {
    throw new InvalidPeriodError(
      `Invalid payroll period "${period}". Month must be between 01 and 12.`
    );
  }

  if (year < 1970 || year > 2999) {
    throw new InvalidPeriodError(
      `Invalid payroll period "${period}". Year must be between 1970 and 2999.`
    );
  }

  return { year, month };
}

/**
 * Returns the Unix timestamp (ms) of the start of a payroll period,
 * interpreted at UTC midnight on the first day of the month.
 *
 * @param period - Period identifier in "YYYY-MM" format
 * @returns Unix timestamp in milliseconds
 */
export function getPeriodStartTimestamp(period: string): number {
  const { year, month } = parsePeriod(period);
  return Date.UTC(year, month - 1, 1, 0, 0, 0, 0);
}

/**
 * Returns the Unix timestamp (ms) of the end of a payroll period,
 * interpreted at UTC midnight on the first day of the following month
 * (exclusive).
 *
 * @param period - Period identifier in "YYYY-MM" format
 * @returns Unix timestamp in milliseconds
 */
export function getPeriodEndTimestamp(period: string): number {
  const { year, month } = parsePeriod(period);
  return Date.UTC(year, month, 1, 0, 0, 0, 0);
}

/**
 * Resolves the canonical payroll period identifier for a Unix timestamp.
 *
 * Payroll periods are always defined in UTC. This function ignores the
 * host timezone and derives the period directly from the UTC calendar,
 * so a timestamp that falls on the last day of a month in a negative
 * offset timezone is not incorrectly attributed to the next month.
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @returns Period identifier in "YYYY-MM" format
 */
export function resolvePeriodForTimestamp(timestamp: number): string {
  if (!Number.isFinite(timestamp)) {
    throw new InvalidPeriodError(
      `Payroll timestamp must be a finite number of milliseconds, received ${timestamp}`
    );
  }

  const date = new Date(timestamp);
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth() + 1;
  return `${year}-${String(month).padStart(2, "0")}`;
}

/**
 * Returns true when the timestamp falls within the given payroll
 * period, using UTC boundaries. The end boundary is exclusive.
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @param period - Period identifier in "YYYY-MM" format
 * @returns True if the timestamp belongs to the period
 */
export function isTimestampInPeriod(timestamp: number, period: string): boolean {
  if (!Number.isFinite(timestamp)) {
    throw new InvalidPeriodError(
      `Payroll timestamp must be a finite number, received ${timestamp}`
    );
  }

  const start = getPeriodStartTimestamp(period);
  const end = getPeriodEndTimestamp(period);
  return timestamp >= start && timestamp < end;
}

/**
 * Returns the number of milliseconds remaining in the given payroll
 * period from the provided timestamp. Returns 0 once the period has
 * ended. This is useful for deadline countdowns that must not be
 * affected by the viewer's local timezone.
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @param period - Period identifier in "YYYY-MM" format
 * @returns Milliseconds remaining, or 0 when the period has ended
 */
export function getRemainingMsInPeriod(timestamp: number, period: string): number {
  if (!Number.isFinite(timestamp)) {
    throw new InvalidPeriodError(
      `Payroll timestamp must be a finite number, received ${timestamp}`
    );
  }

  const end = getPeriodEndTimestamp(period);
  return Math.max(0, end - timestamp);
}

/**
 * Formats a payroll period identifier into a human-readable label.
 *
 * @param period - Period identifier in "YYYY-MM" format (e.g., "2024-01")
 * @returns Human-readable label (e.g., "January 2024")
 */
export function formatPeriod(period: string): string {
  return formatPeriodLabel(period);
}

/**
 * Returns a compact period label (preserves the original "YYYY-MM" format).
 *
 * @param period - Period identifier in "YYYY-MM" format
 * @returns Compact label
 */
export function formatPeriodCompactLabel(period: string): string {
  return formatPeriodCompact(period);
}

/**
 * Formats a Unix timestamp into a period label.
 *
 * The timestamp is resolved in the host's local timezone, matching
 * `formatTimestampToPeriod`. Use `resolvePeriodForTimestamp` when the
 * canonical UTC period is wanted instead.
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @returns Human-readable period label
 */
export function formatTimestamp(timestamp: number): string {
  return formatTimestampToPeriod(timestamp);
}

/**
 * Returns the previous period identifier.
 *
 * @param period - Current period in "YYYY-MM" format
 * @returns Previous period identifier
 */
export function getEarlierPeriod(period: string): string {
  parsePeriod(period);
  return getPreviousPeriod(period);
}

/**
 * Returns the next period identifier.
 *
 * @param period - Current period in "YYYY-MM" format
 * @returns Next period identifier
 */
export function getLaterPeriod(period: string): string {
  parsePeriod(period);
  return getNextPeriod(period);
}

/**
 * Interface for period label configuration options.
 */
export interface PeriodLabelOptions {
  /** Format style: "compact" (default) or "full" */
  style?: "compact" | "full";
  /** Whether to include "Period" prefix */
  includePrefix?: boolean;
  /**
   * Optional IANA timezone used only for display context. Payroll
   * boundaries remain UTC-defined; this value is validated and
   * reported in the resulting label metadata.
   */
  timeZone?: string;
}

/**
 * Format period label with optional configuration.
 *
 * @param period - Period identifier in "YYYY-MM" format
 * @param options - Formatting options
 * @returns Formatted period label
 */
export function formatPeriodWithOptions(period: string, options?: PeriodLabelOptions): string {
  if (options?.timeZone !== undefined) {
    assertValidTimeZone(options.timeZone);
  }

  const style = options?.style ?? "compact";
  const base = style === "full" ? formatPeriodLabel(period) : formatPeriodCompact(period);

  return options?.includePrefix ? `Period ${base}` : base;
}

/**
 * Asserts that a timezone identifier is valid according to the runtime
 * intl API. Throws an InvalidPeriodError with an actionable message
 * when the identifier is not recognized.
 *
 * @param timeZone - IANA timezone identifier (e.g., "Europe/Berlin")
 */
export function assertValidTimeZone(timeZone: string): void {
  if (typeof timeZone !== "string" || timeZone.trim() === "") {
    throw new InvalidPeriodError(
      `Payroll timezone must be a non-empty IANA identifier, received "${timeZone}".`
    );
  }

  try {
    // This throws a RangeError for unknown timezones in all supported
    // runtimes (Node/Deno/browsers).
    new Intl.DateTimeFormat("en-US", { timeZone });
  } catch {
    throw new InvalidPeriodError(
      `Unknown payroll timezone "${timeZone}". Use an IANA identifier such as "UTC" or "Europe/Berlin".`
    );
  }
}

/**
 * Fixture: sample period labels for testing and examples.
 */
export const samplePeriodLabels = {
  "2024-01": "January 2024",
  "2024-06": "June 2024",
  "2024-12": "December 2024",
  "2025-01": "January 2025",
};

/**
 * Edge case: validate period format.
 *
 * @param period - Period identifier to validate
 * @returns True if valid "YYYY-MM" format
 */
export function isValidPeriod(period: string): boolean {
  if (typeof period !== "string") {
    return false;
  }

  // Format-only check by contract: "2024-13" is format-valid even though
  // the month is out of range. Use `parsePeriod` for range validation.
  return /^\d{4}-\d{2}$/.test(period);
}
