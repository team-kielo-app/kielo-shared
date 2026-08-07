"""Tests for kielo_shared.gcs_utils URL helpers."""

from kielo_shared.gcs_utils import ensure_alt_media

SIGNED_URL = (
    "https://storage.googleapis.com/kielo-media-uploads/temp-uploads/abc/video.mp4"
    "?X-Goog-Algorithm=GOOG4-RSA-SHA256"
    "&X-Goog-Credential=sa%40project.iam.gserviceaccount.com%2F20260806%2Fauto%2Fstorage%2Fgoog4_request"
    "&X-Goog-Date=20260806T081044Z&X-Goog-Expires=3599"
    "&X-Goog-Signature=deadbeef&X-Goog-SignedHeaders=host"
)


def test_appends_to_json_api_url():
    url = "http://gcs-emulator:4443/storage/v1/b/bucket/o/path%2Ffile.mp4"
    assert ensure_alt_media(url) == url + "?alt=media"


def test_appends_with_ampersand_when_query_present():
    url = "http://gcs-emulator:4443/storage/v1/b/bucket/o/file.mp4?generation=1"
    assert ensure_alt_media(url) == url + "&alt=media"


def test_idempotent_when_already_present():
    url = "http://gcs-emulator:4443/storage/v1/b/bucket/o/file.mp4?alt=media"
    assert ensure_alt_media(url) == url


def test_signed_url_untouched():
    # A V4 signature covers the query string; appending anything would
    # invalidate it (GCS 403 SignatureDoesNotMatch).
    assert ensure_alt_media(SIGNED_URL) == SIGNED_URL


def test_public_xml_api_url_untouched():
    url = "https://storage.googleapis.com/kielo-public-assets/kielotv/abc/original.mp4"
    assert ensure_alt_media(url) == url
