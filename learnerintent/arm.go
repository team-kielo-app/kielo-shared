package learnerintent

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	ArmOff     = "off"
	ArmHoldout = "holdout"
	ArmTilt    = "tilt"

	// HoldoutSalt is the one intent holdout every surface reads, so a learner
	// is in the control group everywhere or nowhere: per-surface salts gave one
	// learner a personalised KieloTV and an unpersonalised Juka (tutor walk,
	// 2026-10-28). The engine's Python twin uses the same salt and rule.
	HoldoutSalt = "intent_v1:"

	holdoutModulus = 10
)

// ArmFor is "off" while the surface's switch is off, else "holdout" for the
// 10% of learners whose first 4 bytes of sha256(HoldoutSalt + userID),
// big-endian, are divisible by 10, else "tilt".
func ArmFor(enabled bool, userID string) string {
	if !enabled {
		return ArmOff
	}
	sum := sha256.Sum256([]byte(HoldoutSalt + userID))
	if binary.BigEndian.Uint32(sum[:4])%holdoutModulus == 0 {
		return ArmHoldout
	}
	return ArmTilt
}
