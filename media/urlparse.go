package media

import (
	"net/url"
	"strings"
)

// StorageObject is a bucket/object pair recovered from a media URL.
type StorageObject struct {
	Bucket string
	Object string
}

// ParseStorageURL recovers the bucket and object from any URL shape the
// platform has minted for stored media:
//
//	https://storage.googleapis.com/<bucket>/<object>
//	https://media.kielo.app/<bucket>/<object>            (Cloud CDN)
//	https://<edge>/cdn/<bucket>/<object>, /gcs/<bucket>/<object>
//	http://<emulator>/storage/v1/b/<bucket>/o/<escaped>?alt=media
//	http://<emulator>/download/storage/v1/b/<bucket>/o/<escaped>
//	http://<emulator or CDN emulator>/<bucket>/<object> (path style)
//
// Query strings (signatures, alt=media) are ignored. ok is false for a URL
// that is not storage-shaped. Whether the bucket is ours is the caller's
// call (Delivery.ClassOf).
func ParseStorageURL(raw string) (StorageObject, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return StorageObject{}, false
	}
	path := u.EscapedPath()
	if obj, matched, ok := parseJSONAPIPath(path); matched {
		return obj, ok
	}
	for _, edge := range []string{"/cdn/", "/gcs/"} {
		if rest, found := strings.CutPrefix(path, edge); found {
			path = "/" + rest
			break
		}
	}
	bucket, object, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !ok || bucket == "" || object == "" {
		return StorageObject{}, false
	}
	decoded, err := url.PathUnescape(object)
	if err != nil {
		return StorageObject{}, false
	}
	return StorageObject{Bucket: bucket, Object: decoded}, true
}

// parseJSONAPIPath handles the storage JSON-API forms
// (/storage/v1/b/<bucket>/o/<escaped>, optionally under /download). matched
// reports whether the path has that shape at all.
func parseJSONAPIPath(path string) (obj StorageObject, matched, ok bool) {
	for _, api := range []string{"/download/storage/v1/b/", "/storage/v1/b/"} {
		rest, found := strings.CutPrefix(path, api)
		if !found {
			continue
		}
		bucket, object, cut := strings.Cut(rest, "/o/")
		if !cut || bucket == "" {
			return StorageObject{}, true, false
		}
		decoded, err := url.PathUnescape(object)
		if err != nil || decoded == "" {
			return StorageObject{}, true, false
		}
		return StorageObject{Bucket: bucket, Object: decoded}, true, true
	}
	return StorageObject{}, false, false
}
