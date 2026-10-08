package media

import (
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/team-kielo-app/kielo-shared/gcs"
)

// Delivery is the one authority for client-facing media URLs. An access
// class is a storage target: the bucket an asset lives in decides how it may
// be read, so a URL is never more open than its bytes.
//
//	public      CDN URL, unsigned (the bucket is publicly readable)
//	signed_cdn  CDN URL signed with the CDN key (the bucket is private; the
//	            CDN reads it only for a validly signed request)
//	private     no client URL (services read through the media service)
//
// A bucket that is none of the three (legacy rows, foreign buckets) keeps
// the storage URL it always had.
//
// Configured from env (see DeliveryFromEnv); every process uses
// DefaultDelivery so all services mint identical URLs.
type Delivery struct {
	cdnBase      string // canonical, may carry "{bucket}"
	cdnInternal  string // dev only: the CDN emulator as seen from containers
	buckets      map[string]AccessClass
	targets      map[AccessClass]string
	signer       *CDNSigner
	signedTTL    time.Duration
	signedWindow time.Duration
	now          func() time.Time
}

// DeliveryConfig is the explicit form of the env configuration.
type DeliveryConfig struct {
	// CDNBaseURL is the CDN origin, e.g. "https://media.kielo.app/{bucket}".
	CDNBaseURL string
	// CDNInternalBaseURL is set only in dev: the CDN emulator's base as
	// containers reach it, swapped in for Docker-internal callers.
	CDNInternalBaseURL string
	PublicBucket       string
	SignedBucket       string
	PrivateBucket      string
	Signer             *CDNSigner
	// SignedTTL is how long a signed URL stays valid at least (default 1h).
	// Expiry is aligned to SignedWindow (default 1h) so a URL is identical
	// for a whole window and caches keep hitting.
	SignedTTL    time.Duration
	SignedWindow time.Duration
}

// NewDelivery builds a Delivery from cfg.
func NewDelivery(cfg DeliveryConfig) *Delivery {
	d := &Delivery{
		cdnBase:      strings.TrimRight(strings.TrimSpace(cfg.CDNBaseURL), "/"),
		cdnInternal:  strings.TrimRight(strings.TrimSpace(cfg.CDNInternalBaseURL), "/"),
		buckets:      map[string]AccessClass{},
		targets:      map[AccessClass]string{},
		signer:       cfg.Signer,
		signedTTL:    cfg.SignedTTL,
		signedWindow: cfg.SignedWindow,
		now:          time.Now,
	}
	if d.signedTTL <= 0 {
		d.signedTTL = time.Hour
	}
	if d.signedWindow <= 0 {
		d.signedWindow = time.Hour
	}
	for class, bucket := range map[AccessClass]string{
		AccessPublic: cfg.PublicBucket, AccessSignedCDN: cfg.SignedBucket, AccessPrivate: cfg.PrivateBucket,
	} {
		if bucket = strings.TrimSpace(bucket); bucket != "" {
			d.buckets[bucket] = class
			d.targets[class] = bucket
		}
	}
	return d
}

// DeliveryFromEnv reads:
//
//	CDN_SERVING_BASE_URL          CDN origin, "{bucket}" placeholder allowed
//	MEDIA_CDN_INTERNAL_BASE_URL   dev only (CDN emulator from containers)
//	MEDIA_PUBLIC_BUCKET           defaults to PROCESSED_GCS_BUCKET
//	MEDIA_SIGNED_BUCKET, MEDIA_PRIVATE_BUCKET
//	MEDIA_CDN_SIGNING_KEY_NAME, MEDIA_CDN_SIGNING_KEY (base64url, Secret Manager)
//	MEDIA_SIGNED_URL_TTL          Go duration, default 1h
func DeliveryFromEnv() *Delivery {
	cfg := DeliveryConfig{
		CDNBaseURL:         os.Getenv("CDN_SERVING_BASE_URL"),
		CDNInternalBaseURL: os.Getenv("MEDIA_CDN_INTERNAL_BASE_URL"),
		PublicBucket:       firstNonEmptyEnv("MEDIA_PUBLIC_BUCKET", "PROCESSED_GCS_BUCKET"),
		SignedBucket:       os.Getenv("MEDIA_SIGNED_BUCKET"),
		PrivateBucket:      os.Getenv("MEDIA_PRIVATE_BUCKET"),
	}
	if ttl, err := time.ParseDuration(strings.TrimSpace(os.Getenv("MEDIA_SIGNED_URL_TTL"))); err == nil {
		cfg.SignedTTL = ttl
	}
	keyName, key := os.Getenv("MEDIA_CDN_SIGNING_KEY_NAME"), os.Getenv("MEDIA_CDN_SIGNING_KEY")
	if strings.TrimSpace(keyName) != "" || strings.TrimSpace(key) != "" {
		signer, err := NewCDNSigner(keyName, key)
		if err != nil {
			log.Printf("[media-delivery] signed media disabled: %v", err)
		}
		cfg.Signer = signer
	}
	return NewDelivery(cfg)
}

var (
	defaultDeliveryMu sync.RWMutex
	defaultDelivery   *Delivery
)

// DefaultDelivery is the process-wide Delivery, read from env on first use.
func DefaultDelivery() *Delivery {
	defaultDeliveryMu.RLock()
	d := defaultDelivery
	defaultDeliveryMu.RUnlock()
	if d != nil {
		return d
	}
	defaultDeliveryMu.Lock()
	defer defaultDeliveryMu.Unlock()
	if defaultDelivery == nil {
		defaultDelivery = DeliveryFromEnv()
	}
	return defaultDelivery
}

// SetDefaultDelivery replaces the process-wide Delivery (tests, or a service
// that builds its config explicitly). nil resets to "read env on next use".
func SetDefaultDelivery(d *Delivery) {
	defaultDeliveryMu.Lock()
	defaultDelivery = d
	defaultDeliveryMu.Unlock()
}

// ClassOf is the access class of a bucket; ok is false for a bucket that is
// not one of the configured storage targets.
func (d *Delivery) ClassOf(bucket string) (AccessClass, bool) {
	class, ok := d.buckets[strings.TrimSpace(bucket)]
	return class, ok
}

// Buckets is every configured storage target by class.
func (d *Delivery) Buckets() map[AccessClass]string {
	out := make(map[AccessClass]string, len(d.targets))
	for class, bucket := range d.targets {
		out[class] = bucket
	}
	return out
}

// BucketFor is the storage target of an access class ("" when unset).
func (d *Delivery) BucketFor(class AccessClass) string {
	return d.targets[class]
}

// StorageBucketFor is where a new asset of this profile is stored: its access
// class's target, or fallback when that target is not configured (no
// profile, or a stack without a bucket for the class).
func (d *Delivery) StorageBucketFor(profile MediaProfile, hasProfile bool, fallback string) string {
	if hasProfile {
		if bucket := d.BucketFor(profile.Access); bucket != "" {
			return bucket
		}
	}
	return fallback
}

// Signer is the CDN signer, nil when signed media is not configured.
func (d *Delivery) Signer() *CDNSigner { return d.signer }

// CDNBaseURL is the canonical CDN base for a bucket ("" without a CDN).
func (d *Delivery) CDNBaseURL(bucket string) string {
	if d.cdnBase == "" {
		return ""
	}
	return strings.ReplaceAll(d.cdnBase, "{bucket}", bucket)
}

// ObjectURL is the URL a client should use for one object, contextualized for
// the caller's host in dev. "" means no client may have one (private class,
// or signed media without a configured key).
func (d *Delivery) ObjectURL(requestHost, bucket, objectPath string) string {
	objectPath = strings.TrimLeft(strings.TrimSpace(objectPath), "/")
	if bucket == "" || objectPath == "" {
		return ""
	}
	class, known := d.ClassOf(bucket)
	switch {
	case !known:
		return storageObjectURL(requestHost, bucket, objectPath)
	case class == AccessPublic:
		if base := d.CDNBaseURL(bucket); base != "" {
			return d.contextualize(requestHost, base+"/"+objectPath)
		}
		return storageObjectURL(requestHost, bucket, objectPath)
	case class == AccessSignedCDN:
		base := d.CDNBaseURL(bucket)
		if base == "" {
			// No CDN in front (plain local stack): nothing enforces signing,
			// so the storage URL is what reaches the bytes.
			return storageObjectURL(requestHost, bucket, objectPath)
		}
		if d.signer == nil {
			log.Printf("[media-delivery] no CDN signing key; refusing an unsigned URL for %s/%s", bucket, objectPath)
			return ""
		}
		return d.contextualize(requestHost, d.signer.SignURL(base+"/"+escapeObjectPath(objectPath), d.expiry()))
	default:
		return ""
	}
}

// ServeBaseURL is the directory URL old clients join variant paths onto.
// Only a public asset has one: a signed URL cannot be extended with a path,
// and a private asset has no client URL at all.
func (d *Delivery) ServeBaseURL(requestHost, bucket, prefix string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	class, known := d.ClassOf(bucket)
	if known && class != AccessPublic {
		return ""
	}
	if base := d.CDNBaseURL(bucket); known && base != "" {
		if prefix != "" {
			base += "/" + prefix
		}
		return d.contextualize(requestHost, base+"/")
	}
	base := gcs.BuildServeBaseURL(bucket, prefix, "")
	if base == "" {
		return ""
	}
	return gcs.ContextualizeStorageURL(requestHost, base)
}

// expiry is now plus the TTL, rounded up to the next window boundary, so a
// URL minted anywhere in a window is the same string.
func (d *Delivery) expiry() time.Time {
	now := d.now()
	return now.Add(d.signedTTL).Truncate(d.signedWindow).Add(d.signedWindow)
}

// ContextualizeURL points a dev CDN-emulator URL minted for another caller
// at a host this caller can reach (for responses assembled from cached or
// upstream bodies). Production CDN URLs pass through.
func (d *Delivery) ContextualizeURL(requestHost, rawURL string) string {
	return d.contextualize(requestHost, rawURL)
}

// contextualize points a dev CDN-emulator URL at a host the caller can
// reach. Production CDN URLs (no internal base configured) pass through.
func (d *Delivery) contextualize(requestHost, rawURL string) string {
	if d.cdnInternal == "" || d.cdnBase == "" {
		return rawURL
	}
	host := strings.TrimSpace(strings.ToLower(requestHost))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	canonical, err := url.Parse(strings.ReplaceAll(d.cdnBase, "{bucket}", "x"))
	if err != nil || canonical.Host == "" {
		return rawURL
	}
	origin := canonical.Scheme + "://" + canonical.Host
	if !strings.HasPrefix(rawURL, origin) {
		return rawURL
	}
	switch {
	case host != "" && !gcs.IsLoopbackHostname(host) && !strings.Contains(host, "."):
		// A Docker-internal caller (single-label hostname).
		internal, err := url.Parse(strings.ReplaceAll(d.cdnInternal, "{bucket}", "x"))
		if err != nil || internal.Host == "" {
			return rawURL
		}
		return internal.Scheme + "://" + internal.Host + strings.TrimPrefix(rawURL, origin)
	case host != "" && !gcs.IsLoopbackHostname(host) && gcs.IsLoopbackHostname(canonical.Hostname()):
		// A device on the LAN reached us via this host; the emulator's port
		// is published there too.
		return canonical.Scheme + "://" + net.JoinHostPort(host, canonical.Port()) + strings.TrimPrefix(rawURL, origin)
	default:
		return rawURL
	}
}

func storageObjectURL(requestHost, bucket, objectPath string) string {
	base := gcs.BuildServeBaseURL(bucket, "", "")
	if base == "" {
		return ""
	}
	return gcs.JoinServeBaseAndObjectPath(gcs.ContextualizeStorageURL(requestHost, base), objectPath)
}

// escapeObjectPath percent-encodes each segment, so the signed string is the
// one a client sends (a client encodes "ä" before requesting it).
func escapeObjectPath(objectPath string) string {
	parts := strings.Split(objectPath, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
