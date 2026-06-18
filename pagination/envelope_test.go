package pagination

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnvelope_HasMore(t *testing.T) {
	env := NewEnvelope([]int{1, 2, 3}, 3, 0, 10)
	assert.Equal(t, 3, len(env.Items))
	assert.Equal(t, 3, env.Page.Limit)
	assert.Equal(t, 0, env.Page.Offset)
	assert.Equal(t, 10, env.Page.Total)
	assert.True(t, env.Page.HasMore)
}

func TestNewEnvelope_NoMore(t *testing.T) {
	env := NewEnvelope([]int{8, 9, 10}, 3, 7, 10)
	assert.False(t, env.Page.HasMore)
}

func TestNewEnvelope_NilItemsBecomeEmpty(t *testing.T) {
	env := NewEnvelope[int](nil, 10, 0, 0)
	require.NotNil(t, env.Items)
	assert.Equal(t, 0, len(env.Items))

	b, err := json.Marshal(env)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"items":[]`)
}

func TestEnvelope_JSONShape(t *testing.T) {
	env := Envelope[string]{
		Items: []string{"a"},
		Page:  Page{Limit: 1, Offset: 0, Total: 5, HasMore: true},
	}
	b, err := json.Marshal(env)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"items":["a"],"page":{"limit":1,"offset":0,"total":5,"has_more":true}}`,
		string(b),
	)
}
