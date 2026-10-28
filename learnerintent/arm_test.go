package learnerintent

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArmForSplitsAboutTenPercent(t *testing.T) {
	holdout := 0
	for i := 0; i < 10000; i++ {
		if ArmFor(true, fmt.Sprintf("00000000-0000-0000-0000-%012d", i)) == ArmHoldout {
			holdout++
		}
	}
	assert.InDelta(t, 1000, holdout, 120)
	assert.Equal(t, ArmOff, ArmFor(false, "anyone"))
}

func TestArmForVectorsMatchThePythonRule(t *testing.T) {
	// Python: int.from_bytes(sha256(("intent_v1:" + id).encode()).digest()[:4], "big") % 10 == 0
	for id, want := range map[string]string{
		"3fb6a010-3ecb-49df-815f-f10f141b0bb8": ArmTilt,
		"48a140a8-2b47-460f-b76f-05fe6977efcc": ArmTilt,
		"00000000-0000-0000-0000-000000000007": ArmHoldout,
	} {
		assert.Equal(t, want, ArmFor(true, id), id)
	}
}
