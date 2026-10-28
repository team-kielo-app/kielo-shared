package ranktie

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var day = time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)

func TestKeyMatchesDocumentedFormula(t *testing.T) {
	sum := sha256.Sum256([]byte("user-1|2026-10-28|item-9"))
	var want uint64
	for _, b := range sum[:8] {
		want = want<<8 | uint64(b)
	}
	assert.Equal(t, want, Key("user-1", day, "item-9"))
	assert.Equal(t, "user-1|2026-10-28|item-9", Input("user-1", day, "item-9"))
}

func TestKeyStableWithinADayAndUTC(t *testing.T) {
	a := Key("u", day, "x")
	assert.Equal(t, a, Key("u", day.Add(23*time.Hour+59*time.Minute), "x"))
	helsinki := time.FixedZone("EET", 3*3600)
	assert.Equal(t, a, Key("u", time.Date(2026, 10, 28, 5, 0, 0, 0, helsinki), "x"), "05:00 EET is 02:00 UTC, the same UTC day")
	assert.NotEqual(t, a, Key("u", time.Date(2026, 10, 28, 1, 0, 0, 0, helsinki), "x"), "01:00 EET on the 28th is still the 27th in UTC")
}

func TestKeyDiffersAcrossLearnersDaysItems(t *testing.T) {
	base := Key("u1", day, "x")
	assert.NotEqual(t, base, Key("u2", day, "x"))
	assert.NotEqual(t, base, Key("u1", day.AddDate(0, 0, 1), "x"))
	assert.NotEqual(t, base, Key("u1", day, "y"))
}

func TestDifferentLearnersOrderTiesDifferently(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	order := func(user string) string {
		out := append([]string(nil), items...)
		for i := 1; i < len(out); i++ {
			for j := i; j > 0 && Key(user, day, out[j]) < Key(user, day, out[j-1]); j-- {
				out[j], out[j-1] = out[j-1], out[j]
			}
		}
		return strings.Join(out, "")
	}
	seen := map[string]bool{}
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5", "u6"} {
		seen[order(u)] = true
	}
	assert.Greater(t, len(seen), 3)
}

func TestSignedIsInt64OfKey(t *testing.T) {
	for _, item := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		assert.Equal(t, int64(Key("u", day, item)), Signed("u", day, item))
	}
}

// sqlByHand evaluates SQL's formula step by step on the same hex string
// Postgres produces: encode(sha256(..), 'hex'), substr(.., 1, 16), then
// ('x' || that)::bit(64)::bigint, a two's-complement signed read.
func sqlByHand(user, dayText, item string) int64 {
	sum := sha256.Sum256([]byte(user + "|" + dayText + "|" + item))
	hexText := hex.EncodeToString(sum[:])
	bits, err := strconv.ParseUint(hexText[:16], 16, 64)
	if err != nil {
		panic(err)
	}
	return int64(bits)
}

func TestGoAndSQLFormulasAgreeOnVectors(t *testing.T) {
	vectors := []struct{ user, item string }{
		{"user-1", "item-9"},
		{"00000000-0000-0000-0000-000000000001", "11111111-1111-1111-1111-111111111111"},
		{"u", ""},
		{"", "x"},
		{"käyttäjä", "äö"},
	}
	for _, v := range vectors {
		for _, d := range []time.Time{day, day.AddDate(0, 0, 1), time.Date(2027, 1, 1, 12, 30, 0, 0, time.UTC)} {
			want := sqlByHand(v.user, d.Format("2006-01-02"), v.item)
			assert.Equal(t, want, Signed(v.user, d, v.item), "%v %v", v, d)
		}
	}
	negative := false
	for i := range 64 {
		if Signed("u", day, strconv.Itoa(i)) < 0 {
			negative = true
		}
	}
	assert.True(t, negative, "vectors cover the signed (high bit set) case")
}

func TestSQLShape(t *testing.T) {
	sql := SQL("$1", "$2::date", "c.id")
	require.Equal(t, strings.Count(sql, "("), strings.Count(sql, ")"), "balanced parentheses")
	for _, part := range []string{
		"convert_to(($1)::text || '|' || to_char(($2::date)::date, 'YYYY-MM-DD') || '|' || (c.id)::text, 'UTF8')",
		"sha256(",
		"encode(",
		"'hex'",
		"substr(",
		"1, 16",
		"'x' ||",
		"::bit(64)::bigint",
	} {
		assert.Contains(t, sql, part)
	}
}
