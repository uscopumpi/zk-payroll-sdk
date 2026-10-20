import { ValidationError, ContractExecutionError } from "../core/errors";
import { normalizeAssetSymbol } from "./symbols";

/**
 * Raw asset shape as it may be returned from a Soroban contract or
 * off-chain config endpoint. Dashboard code should not have to reason
 * about this shape directly – use the typed helpers below.
 */
export interface RawSupportedAsset {
  symbol: string;
  address?: string;
  contractId?: string;
  decimals?: number;
  name?: string;
  enabled?: boolean;
}

/**
 * Typed, normalized view of a supported payroll asset.
 * `symbol` is always the canonical upper-cased form.
 */
export interface SupportedAsset {
  /** Canonical normalized symbol, e.g. "USDC" */
  symbol: string;
  /** Same as `symbol` – kept as alias for backwards-compat with dashboards that expect `normalizedSymbol` */
  normalizedSymbol: string;
  /** Soroban token contract ID, or null for native XLM */
  contractId: string | null;
  /** Number of decimals (Stellar default 7) */
  decimals: number;
  /** Human-readable name (defaults to symbol) */
  name: string;
  /** Whether the asset is currently enabled for payroll */
  enabled: boolean;
  /** Display-ready form (same as symbol, safe to render) */
  displaySymbol: string;
}

type RawInput = unknown;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Normalizes a single raw asset entry to a typed `SupportedAsset`.
 *
 * Accepts either:
 *  - a plain string   -> treated as `{ symbol: value }`
 *  - an object with a `symbol` field (and optional address/contractId/decimals/name/enabled)
 *
 * Privacy: never logs payroll-sensitive values (amount/recipient). Only the
 * asset symbol and its metadata are inspected.
 *
 * @throws ValidationError with an actionable message when the entry is malformed
 */
export function normalizeSupportedAsset(raw: RawInput): SupportedAsset {
  let symbolRaw: unknown;
  let contractIdRaw: unknown;
  let decimalsRaw: unknown;
  let nameRaw: unknown;
  let enabledRaw: unknown;

  if (typeof raw === "string") {
    symbolRaw = raw;
  } else if (isRecord(raw)) {
    // Support multiple casing conventions from different contract versions
    symbolRaw = (raw.symbol ?? raw.Symbol ?? raw.asset ?? raw.token) as unknown;
    contractIdRaw = (raw.contractId ?? raw.contract_id ?? raw.address ?? raw.tokenId) as unknown;
    decimalsRaw = (raw.decimals ?? raw.decimal) as unknown;
    nameRaw = (raw.name ?? raw.displayName) as unknown;
    enabledRaw = (raw.enabled ?? raw.active ?? raw.isEnabled) as unknown;
  } else {
    throw new ValidationError(
      "Supported asset entry must be a string or an object with a 'symbol' field",
      "asset",
      "VALIDATION_ERROR",
      { receivedType: typeof raw }
    );
  }

  const symbol = normalizeAssetSymbol(symbolRaw);

  // contractId: null for native, otherwise trimmed string. Empty string -> null.
  let contractId: string | null = null;
  if (typeof contractIdRaw === "string") {
    const trimmed = contractIdRaw.trim();
    contractId = trimmed.length > 0 ? trimmed : null;
  } else if (contractIdRaw !== null && contractIdRaw !== undefined) {
    throw new ValidationError("Asset contractId must be a string when provided", "asset");
  }

  // Native asset has no contractId; keep null. Enforce that native assets are consistently represented.
  // No further validation of StrKey shape here – that's the adapter layer's job.

  let decimals = 7; // Stellar default
  if (decimalsRaw !== undefined && decimalsRaw !== null) {
    if (
      typeof decimalsRaw !== "number" ||
      !Number.isInteger(decimalsRaw) ||
      decimalsRaw < 0 ||
      decimalsRaw > 18
    ) {
      throw new ValidationError(
        `Asset decimals must be an integer between 0 and 18 (received ${String(decimalsRaw)})`,
        "asset"
      );
    }
    decimals = decimalsRaw;
  }

  let name = symbol;
  if (typeof nameRaw === "string" && nameRaw.trim().length > 0) {
    name = nameRaw.trim();
  } else if (nameRaw !== null && nameRaw !== undefined && typeof nameRaw !== "string") {
    throw new ValidationError("Asset name must be a string when provided", "asset");
  }

  let enabled = true;
  if (typeof enabledRaw === "boolean") {
    enabled = enabledRaw;
  } else if (enabledRaw !== null && enabledRaw !== undefined && typeof enabledRaw !== "boolean") {
    throw new ValidationError("Asset enabled flag must be a boolean when provided", "asset");
  }

  return {
    symbol,
    normalizedSymbol: symbol,
    contractId,
    decimals,
    name,
    enabled,
    displaySymbol: symbol,
  };
}

/**
 * Normalizes a raw list response into a typed array.
 *
 * @param rawList - Expected to be an array of strings and/or objects
 * @returns Typed, normalized assets
 * @throws ValidationError when the input is not an array or contains invalid entries
 */
export function normalizeSupportedAssets(rawList: unknown): SupportedAsset[] {
  if (!Array.isArray(rawList)) {
    throw new ValidationError(
      "Supported assets response must be an array — received " + typeof rawList,
      "assets"
    );
  }

  const normalized: SupportedAsset[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < rawList.length; i++) {
    try {
      const asset = normalizeSupportedAsset(rawList[i]);
      if (seen.has(asset.symbol)) {
        // De-duplicate by symbol, keep first occurrence – dashboard expects unique symbols.
        continue;
      }
      seen.add(asset.symbol);
      normalized.push(asset);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new ValidationError(
        `Invalid supported asset at index ${i}: ${msg}. Expected a string symbol like "USDC" or an object { symbol: "USDC", contractId: "C..." }.`,
        "assets"
      );
    }
  }

  return normalized;
}

/**
 * Alias for backwards-compatibility with older dashboards that import
 * `parseSupportedAssets`. Same behaviour as `normalizeSupportedAssets`.
 */
export const parseSupportedAssets = normalizeSupportedAssets;

/**
 * Client-side helper that fetches raw assets via a provider and returns
 * typed, normalized results. This prevents dashboard code from having to
 * understand raw ScVal / RPC response shapes.
 *
 * @param fetcher - Async function that returns the raw contract response (array of strings/objects)
 * @returns Normalized supported assets
 * @throws ContractExecutionError / ValidationError with actionable messages
 *
 * @example
 * const assets = await getSupportedAssets(() => registryClient.getSupportedAssets(signer));
 */
export async function getSupportedAssets(
  fetcher: () => Promise<unknown>
): Promise<SupportedAsset[]> {
  let raw: unknown;
  try {
    raw = await fetcher();
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    // Preserve original context but surface an actionable remediation
    throw new ContractExecutionError(
      `Failed to fetch supported assets: ${msg}. Verify the contract is deployed, the RPC URL is reachable, and the signer has sufficient permissions.`,
      "UNKNOWN_RPC_ERROR",
      { cause: msg }
    );
  }

  try {
    return normalizeSupportedAssets(raw);
  } catch (error) {
    // Re-throw ValidationErrors unchanged – no need to wrap them again
    if (error instanceof ValidationError) throw error;
    const msg = error instanceof Error ? error.message : String(error);
    throw new ValidationError(
      `Failed to normalize supported assets response: ${msg}. The contract may have returned an unexpected shape.`,
      "assets"
    );
  }
}

/**
 * Convenience helper that mirrors the `SupportedAssetsClient` pattern but
 * remains framework-agnostic. Returns enabled assets only when requested.
 */
export async function getEnabledSupportedAssets(
  fetcher: () => Promise<unknown>
): Promise<SupportedAsset[]> {
  const all = await getSupportedAssets(fetcher);
  return all.filter((a) => a.enabled);
}

/**
 * Result of an asset availability check.
 */
export interface AssetAvailabilityResult {
  /** Whether the asset is available for payroll operations */
  available: boolean;
  /** The normalized asset if found */
  asset: SupportedAsset | null;
  /** Human-readable reason when the asset is not available */
  reason?: string;
  /** Machine-readable code for the availability state */
  code: AssetAvailabilityCode;
}

/**
 * Machine-readable codes describing why an asset is available or not.
 */
export type AssetAvailabilityCode =
  "AVAILABLE" | "ASSET_NOT_FOUND" | "ASSET_DISABLED" | "ASSET_MISSING_CONTRACT";

/**
 * Options for `checkAssetAvailability`.
 */
export interface AssetAvailabilityOptions {
  /**
   * Whether a native asset (XLM, no contractId) is acceptable.
   * Defaults to true. Set to false to require a token contract.
   */
  allowNative?: boolean;
  /**
   * Whether disabled assets should be treated as available.
   * Defaults to false.
   */
  allowDisabled?: boolean;
}

/**
 * Checks whether an asset identified by symbol is available for payroll
 * operations given a list of supported assets.
 *
 * This is a pure, side-effect-free function suitable for use as a pre-flight
 * safety check before building or submitting a payroll transaction. It never
 * throws for an unknown asset; instead it returns a descriptive result so callers
 * can decide how to surface the error.
 *
 * @param symbol - Asset symbol (case-insensitive), e.g. "usdc"
 * @param assets - Normalized supported assets to search
 * @param options - Availability policy flags
 * @returns An availability result with a machine-readable code
 *
 * @example
 * const { available, reason } = checkAssetAvailability("USDC", assets);
 * if (!available) throw new ValidationError(reason);
 */
export function checkAssetAvailability(
  symbol: unknown,
  assets: SupportedAsset[],
  options: AssetAvailabilityOptions = {}
): AssetAvailabilityResult {
  if (!Array.isArray(assets)) {
    throw new ValidationError("Assets must be an array of normalized supported assets", "assets");
  }

  const normalizedSymbol = normalizeAssetSymbol(symbol);
  const allowNative = options.allowNative ?? true;
  const allowDisabled = options.allowDisabled ?? false;

  const match = assets.find((a) => a.symbol === normalizedSymbol);

  if (!match) {
    return {
      available: false,
      asset: null,
      code: "ASSET_NOT_FOUND",
      reason: `Asset "${normalizedSymbol}" is not in the list of supported assets.`,
    };
  }

  if (!allowDisabled && !match.enabled) {
    return {
      available: false,
      asset: match,
      code: "ASSET_DISABLED",
      reason: `Asset "${normalizedSymbol}" is currently disabled for payroll.`,
    };
  }

  if (!allowNative && match.contractId === null) {
    return {
      available: false,
      asset: match,
      code: "ASSET_MISSING_CONTRACT",
      reason: `Asset "${normalizedSymbol}" is native and has no token contract, but native assets are not allowed.`,
    };
  }

  return {
    available: true,
    asset: match,
    code: "AVAILABLE",
  };
}

/**
 * Convenience wrapper that fetches supported assets and checks availability
 * in a single call. This is the recommended entry point for payroll flows that
 * need to fail fast with an actionable error before building a transaction.
 *
 * @param symbol - Asset symbol to verify (case-insensitive)
 * @param fetcher - Async function returning the raw supported assets response
 * @param options - Availability policy flags
 * @throws ValidationError when the asset is not available
 */
export async function assertAssetAvailable(
  symbol: unknown,
  fetcher: () => Promise<unknown>,
  options: AssetAvailabilityOptions = {}
): Promise<SupportedAsset> {
  const assets = await getSupportedAssets(fetcher);
  const result = checkAssetAvailability(symbol, assets, options);

  if (!result.available || result.asset === null) {
    throw new ValidationError(
      result.reason ?? `Asset ${String(symbol)} is not available for payroll.`,
      "asset",
      "VALIDATION_ERROR",
      { code: result.code }
    );
  }

  return result.asset;
}
