package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Reader hands out the pool for reads that never follow their own write: admin
// screens, reports, background scans. On PlanetScale those can run on a
// replica, which the primary's pooler cannot route to: a replica is reached on
// the direct port with "|replica" appended to the username.
//
// The primary is the system's first ceiling (prod 2026-11-12: 70% CPU on
// average and 100% at p95 on 1/16 vCPU, 68% of its query time SELECTs, two
// replicas with no client). A read that can wait a few seconds for a write to
// arrive belongs on a replica; a read inside a learner's own write path does
// not.
//
// Off unless DB_REPLICA_READS is on. Without a replica, and whenever the
// replica is unreachable or further behind than the lag limit, Pool returns
// the primary, so a caller never has to care which one it got.
type Reader struct {
	primary *pgxpool.Pool
	replica *pgxpool.Pool
	maxLag  time.Duration

	now   func() time.Time
	probe func(ctx context.Context) (time.Duration, error)

	mu        sync.Mutex
	checkedAt time.Time
	healthy   bool
}

const (
	defaultReplicaMaxConns int32 = 2
	defaultReplicaMaxLag         = 30 * time.Second
	replicaRecheckEvery          = 15 * time.Second
	replicaProbeTimeout          = 2 * time.Second
	replicaIdleTime              = 2 * time.Minute
	replicaUserSuffix            = "|replica"
	replicaPort                  = "5432"
	planetScaleHostSuffix        = ".psdb.cloud"
)

// replicaLagSQL is zero when everything received has been replayed, so an idle
// primary does not read as a lagging replica.
const replicaLagSQL = `SELECT CASE
  WHEN NOT pg_is_in_recovery() THEN 0
  WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0
  ELSE COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()), 0)
END::float8`

var errNoReplicaRoute = errors.New("no replica route for this database host")

// ReplicaDSN derives the replica connection string from the primary's: the
// direct port and the "|replica" username. DATABASE_REPLICA_URL wins when set.
// Only PlanetScale hosts have this route; anything else is an error and the
// caller stays on the primary.
func ReplicaDSN(primaryDSN string) (string, error) {
	if explicit := EnvString("DATABASE_REPLICA_URL", ""); explicit != "" {
		return explicit, nil
	}
	u, err := url.Parse(strings.TrimSpace(primaryDSN))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil {
		return "", fmt.Errorf("replica dsn: the primary is not a postgres URL")
	}
	if !strings.HasSuffix(strings.ToLower(u.Hostname()), planetScaleHostSuffix) {
		return "", errNoReplicaRoute
	}
	name := u.User.Username()
	if !strings.HasSuffix(name, replicaUserSuffix) {
		name += replicaUserSuffix
	}
	if password, ok := u.User.Password(); ok {
		u.User = url.UserPassword(name, password)
	} else {
		u.User = url.User(name)
	}
	u.Host = u.Hostname() + ":" + replicaPort
	return u.String(), nil
}

func replicaReadsOn() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DB_REPLICA_READS"))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// NewReader returns the reader for a service's primary pool. It never fails
// and never connects at start: with the switch off, a host that has no
// replicas or a replica that is down, reads go to the primary.
func NewReader(primary *pgxpool.Pool, primaryDSN string) *Reader {
	r := &Reader{primary: primary, maxLag: replicaMaxLag(), now: time.Now}
	if !replicaReadsOn() {
		return r
	}
	dsn, err := ReplicaDSN(primaryDSN)
	if err != nil {
		log.Printf("INFO: DB_REPLICA_READS is on but reads stay on the primary: %v", err)
		return r
	}
	cfg, err := PoolConfig(dsn, PoolOptions{})
	if err != nil {
		log.Printf("WARN: replica pool config failed, reads stay on the primary: %v", err)
		return r
	}
	// A replica connection is a backend of its own on a small machine, and
	// there is no pooler in front of it: a few per instance, none held idle.
	cfg.MaxConns = EnvInt32("PGX_REPLICA_MAX_CONNS", defaultReplicaMaxConns)
	cfg.MinConns = 0
	cfg.MaxConnIdleTime = replicaIdleTime
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		log.Printf("WARN: replica pool failed, reads stay on the primary: %v", err)
		return r
	}
	r.replica = pool
	r.probe = func(ctx context.Context) (time.Duration, error) {
		var seconds float64
		if err := pool.QueryRow(ctx, replicaLagSQL).Scan(&seconds); err != nil {
			return 0, err
		}
		return time.Duration(seconds * float64(time.Second)), nil
	}
	return r
}

func replicaMaxLag() time.Duration {
	seconds := EnvInt32("DB_REPLICA_MAX_LAG_S", int32(defaultReplicaMaxLag/time.Second))
	return time.Duration(seconds) * time.Second
}

// Pool is the pool to read from now: the replica while it answers and is
// within the lag limit, the primary otherwise. The replica is asked at most
// once per recheck interval, inside the call that finds the answer stale.
func (r *Reader) Pool(ctx context.Context) *pgxpool.Pool {
	if r == nil {
		return nil
	}
	if r.replica == nil || r.probe == nil {
		return r.primary
	}
	if r.replicaUsable(ctx) {
		return r.replica
	}
	return r.primary
}

// OnReplica reports whether Pool would hand out the replica right now, for
// logs and health pages.
func (r *Reader) OnReplica(ctx context.Context) bool {
	return r != nil && r.replica != nil && r.probe != nil && r.replicaUsable(ctx)
}

func (r *Reader) replicaUsable(ctx context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.checkedAt.IsZero() && r.now().Sub(r.checkedAt) < replicaRecheckEvery {
		return r.healthy
	}
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), replicaProbeTimeout)
	defer cancel()
	lag, err := r.probe(probeCtx)
	usable := err == nil && lag <= r.maxLag
	if usable != r.healthy || r.checkedAt.IsZero() {
		switch {
		case err != nil:
			log.Printf("WARN: replica reads off, using the primary: %v", err)
		case !usable:
			log.Printf("WARN: replica reads off, using the primary: replica is %s behind (limit %s)", lag.Round(time.Second), r.maxLag)
		default:
			log.Printf("INFO: replica reads on (replica %s behind)", lag.Round(time.Millisecond))
		}
	}
	r.healthy = usable
	r.checkedAt = r.now()
	return usable
}

// Close closes the replica pool. The primary belongs to its owner.
func (r *Reader) Close() {
	if r != nil && r.replica != nil {
		r.replica.Close()
	}
}
