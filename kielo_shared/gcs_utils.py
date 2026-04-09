"""
Kielo GCS utilities — language-agnostic helpers derived from kielo-shared/gcs.json.

Usage:
    from kielo_shared.gcs_utils import ensure_alt_media, build_object_url, is_storage_api_path, BUCKETS
"""

import json
import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse, quote

_CONFIG_PATH = Path(__file__).parent / "gcs.json"
_CONFIG = json.loads(_CONFIG_PATH.read_text())

STORAGE_API_PATH: str = _CONFIG["storageAPIPath"]
UPLOAD_API_PATH: str = _CONFIG["uploadAPIPath"]
ALT_MEDIA_PARAM: str = _CONFIG["altMediaParam"]
DEFAULT_EMULATOR_PORT: int = _CONFIG["defaultEmulatorPort"]
BUCKETS: dict[str, str] = _CONFIG["buckets"]
ENV_VARS: dict[str, str] = _CONFIG["envVars"]


def is_storage_api_path(url_path: str) -> bool:
    """Check if a URL path is a GCS storage API path."""
    return url_path.startswith(STORAGE_API_PATH) or url_path.startswith(UPLOAD_API_PATH)


def ensure_alt_media(url: str) -> str:
    """Append ?alt=media to a URL if not already present."""
    if ALT_MEDIA_PARAM in url:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{ALT_MEDIA_PARAM}"


def build_object_url(base: str, bucket: str, object_path: str) -> str:
    """Build a GCS object URL: {base}/storage/v1/b/{bucket}/o/{encoded_object}"""
    base = base.rstrip("/")
    if base.endswith("/storage/v1"):
        base = base[: -len("/storage/v1")]
    if base.endswith("/storage"):
        base = base[: -len("/storage")]
    encoded = quote(object_path, safe="")
    return f"{base}{STORAGE_API_PATH}{bucket}/o/{encoded}"


def build_object_fetch_url(base: str, bucket: str, object_path: str) -> str:
    """Build a GCS object URL with ?alt=media for fetching content."""
    return build_object_url(base, bucket, object_path) + f"?{ALT_MEDIA_PARAM}"


def get_emulator_host() -> str:
    """Get the normalized emulator host from STORAGE_EMULATOR_HOST env var."""
    raw = os.getenv(ENV_VARS["emulatorHost"], "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port or DEFAULT_EMULATOR_PORT}"


def get_internal_emulator_host() -> str:
    """Get the internal Docker emulator host, rewriting localhost to gcs-emulator."""
    host = get_emulator_host()
    if not host:
        return ""
    parsed = urlparse(host)
    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return f"{parsed.scheme}://gcs-emulator:{parsed.port or DEFAULT_EMULATOR_PORT}"
    return host


def normalize_internal_storage_url(url: str) -> str:
    """Rewrite external emulator URLs to internal Docker hostname."""
    parsed = urlparse(url)
    if not is_storage_api_path(parsed.path):
        return url
    internal = get_internal_emulator_host()
    if not internal:
        return url
    internal_parsed = urlparse(internal)
    if parsed.hostname == internal_parsed.hostname:
        return url
    return urlunparse(parsed._replace(
        scheme=internal_parsed.scheme,
        netloc=f"{internal_parsed.hostname}:{internal_parsed.port or DEFAULT_EMULATOR_PORT}",
    ))
