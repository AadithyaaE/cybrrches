import type { NetworkStateSummary, NetworkStateWindow, FeatureRanges } from "../types/networkState";

/**
 * Data access for the Network State page. Currently backed by static JSON
 * snapshots (generated from the Feature 5/6 research artifacts:
 * data/processed/temporal/temporal_windows.csv and
 * data/processed/temporal/sequences/sequence_metadata.csv) because the
 * research pipeline does not yet expose a live API.
 *
 * The full 32,068-window / 331,027-state artifacts are not shipped to the
 * browser; network_state_windows.json is a representative, evenly-spaced
 * sample of 402 real windows. Every value in it is a real artifact value,
 * never fabricated or interpolated.
 *
 * Callers depend only on this module's async functions, so swapping the
 * fetch() calls below for real API requests later requires no changes
 * to consuming components.
 */

let summaryCache: Promise<NetworkStateSummary> | null = null;
let windowsCache: Promise<NetworkStateWindow[]> | null = null;
let featureRangesCache: Promise<FeatureRanges> | null = null;

export function getNetworkStateSummary(): Promise<NetworkStateSummary> {
  if (!summaryCache) {
    summaryCache = fetch("/data/network_state_summary.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load network state summary: ${res.status}`);
      return res.json();
    });
  }
  return summaryCache;
}

export function getNetworkStateWindows(): Promise<NetworkStateWindow[]> {
  if (!windowsCache) {
    windowsCache = fetch("/data/network_state_windows.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load network state windows: ${res.status}`);
      return res.json();
    });
  }
  return windowsCache;
}

export function getFeatureRanges(): Promise<FeatureRanges> {
  if (!featureRangesCache) {
    featureRangesCache = fetch("/data/network_state_feature_ranges.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load feature ranges: ${res.status}`);
      return res.json();
    });
  }
  return featureRangesCache;
}
