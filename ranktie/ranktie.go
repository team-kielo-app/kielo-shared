// Package ranktie is a per-learner, per-day tie-break for rankers. Items that
// score equally would otherwise sort alphabetically or by recency, so every
// learner at a level sees the same order. Key hashes learner, UTC day and item,
// so the order is stable within a day and differs across learners and days.
package ranktie

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Input is the string that is hashed: userID, the UTC day as YYYY-MM-DD, and
// itemID, joined by "|".
func Input(userID string, day time.Time, itemID string) string {
	return userID + "|" + day.UTC().Format("2006-01-02") + "|" + itemID
}

// Key is the first 8 bytes of sha256(Input), big-endian. Order Go-side
// candidates by it ascending.
func Key(userID string, day time.Time, itemID string) uint64 {
	sum := sha256.Sum256([]byte(Input(userID, day, itemID)))
	return binary.BigEndian.Uint64(sum[:8])
}

// Signed is Key reinterpreted as int64: the value SQL's
// ('x' || hex)::bit(64)::bigint yields for the same bytes, since bigint is
// signed. Order by Signed (not Key) when a Go ranker must agree with a SQL
// ranker that orders by SQL's expression.
func Signed(userID string, day time.Time, itemID string) int64 {
	return int64(Key(userID, day, itemID))
}

// SQL is the Postgres expression equal to Signed for the given SQL
// expressions, so a ranker can ORDER BY it. userExpr and itemExpr are text
// expressions (anything castable to text), dayExpr is a date expression
// already in UTC (for example (now() AT TIME ZONE 'UTC')::date); a timestamptz
// would be cast to date in the session time zone, so convert it first.
//
//	ORDER BY score DESC, <SQL($1, $2::date, c.id::text)>
func SQL(userExpr, dayExpr, itemExpr string) string {
	return "(('x' || substr(encode(sha256(convert_to(" +
		"(" + userExpr + ")::text || '|' || to_char((" + dayExpr + ")::date, 'YYYY-MM-DD') || '|' || (" + itemExpr + ")::text" +
		", 'UTF8')), 'hex'), 1, 16))::bit(64)::bigint)"
}
