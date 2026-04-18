/**
 * Kielo GCS utilities — language-agnostic helpers derived from kielo-shared/gcs.json.
 *
 * Usage:
 *   import { ensureAltMedia, buildObjectUrl, isStorageApiPath, BUCKETS } from "@kielo/shared/gcs_utils";
 */

import config from "../gcs.json";

export const STORAGE_API_PATH: string = config.storageAPIPath;
export const UPLOAD_API_PATH: string = config.uploadAPIPath;
export const ALT_MEDIA_PARAM: string = config.altMediaParam;
export const DEFAULT_EMULATOR_PORT: number = config.defaultEmulatorPort;
export const BUCKETS = config.buckets;
export const ENV_VARS = config.envVars;

/** Check if a URL path is a GCS storage API path. */
export function isStorageApiPath(urlPath: string): boolean {
  return urlPath.startsWith(STORAGE_API_PATH) || urlPath.startsWith(UPLOAD_API_PATH);
}

/**
 * Append ?alt=media to a URL if not already present.
 * Skips non-remote schemes (data:, file:, ph:, blob:) and no-ops if the
 * param is already there. Uses WHATWG URL parsing when available so
 * pre-existing query strings are preserved correctly.
 */
export function ensureAltMedia(url: string): string {
  if (
    !url ||
    url.startsWith("data:") ||
    url.startsWith("file:") ||
    url.startsWith("ph:") ||
    url.startsWith("blob:") ||
    url.includes(ALT_MEDIA_PARAM)
  ) {
    return url;
  }

  try {
    const parsed = new URL(url);
    if (parsed.searchParams.get("alt") !== "media") {
      parsed.searchParams.set("alt", "media");
    }
    return parsed.toString();
  } catch {
    const separator = url.includes("?") ? "&" : "?";
    return `${url}${separator}${ALT_MEDIA_PARAM}`;
  }
}

/** Build a GCS object URL: {base}/storage/v1/b/{bucket}/o/{encodedObject} */
export function buildObjectUrl(base: string, bucket: string, objectPath: string): string {
  let b = base.replace(/\/+$/, "");
  if (b.endsWith("/storage/v1")) b = b.slice(0, -"/storage/v1".length);
  if (b.endsWith("/storage")) b = b.slice(0, -"/storage".length);
  return `${b}${STORAGE_API_PATH}${bucket}/o/${encodeURIComponent(objectPath)}`;
}

/** Build a GCS object URL with ?alt=media for fetching content. */
export function buildObjectFetchUrl(base: string, bucket: string, objectPath: string): string {
  return `${buildObjectUrl(base, bucket, objectPath)}?${ALT_MEDIA_PARAM}`;
}
