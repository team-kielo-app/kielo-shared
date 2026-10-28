package audience

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Query is SQL plus the arguments for its placeholders.
type Query struct {
	SQL  string
	Args []any
}

const realLearner = "EXISTS (SELECT 1 FROM users.learner_class_v1 lc WHERE lc.user_id = u.id AND lc.class = 'real')"

type builder struct {
	first int
	args  []any
}

func (b *builder) arg(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(b.first+len(b.args)-1)
}

func (d Definition) where(firstArg int) (string, []any, error) {
	if firstArg < 1 {
		return "", nil, errors.New("placeholders are numbered from 1")
	}
	if err := d.Validate(); err != nil {
		return "", nil, err
	}
	b := &builder{first: firstArg}
	parts := make([]string, 0, len(d.All)+1)
	parts = append(parts, realLearner)
	for _, c := range d.All {
		cond, err := c.compile()
		if err != nil {
			return "", nil, err
		}
		parts = append(parts, cond(b))
	}
	return strings.Join(parts, " AND "), b.args, nil
}

// Members selects the ids of the learners in the audience. Placeholders are numbered from firstArg.
func (d Definition) Members(firstArg int) (Query, error) {
	where, args, err := d.where(firstArg)
	if err != nil {
		return Query{}, err
	}
	return Query{SQL: "SELECT u.id FROM users.users u WHERE " + where, Args: args}, nil
}

// Count counts the learners in the audience.
func (d Definition) Count(firstArg int) (Query, error) {
	where, args, err := d.where(firstArg)
	if err != nil {
		return Query{}, err
	}
	return Query{SQL: "SELECT count(*) FROM users.users u WHERE " + where, Args: args}, nil
}

// Member asks whether one learner is in the audience. The learner id is the caller's placeholder $userArg
// (a uuid); Args holds only the audience's own arguments, numbered from firstArg.
func (d Definition) Member(userArg, firstArg int) (Query, error) {
	where, args, err := d.where(firstArg)
	if err != nil {
		return Query{}, err
	}
	if userArg < 1 || (userArg >= firstArg && userArg < firstArg+len(args)) {
		return Query{}, fmt.Errorf("placeholder $%d for the learner clashes with the audience's own placeholders", userArg)
	}
	sql := "SELECT EXISTS (SELECT 1 FROM users.users u WHERE u.id = $" + strconv.Itoa(userArg) + "::uuid AND " + where + ")"
	return Query{SQL: sql, Args: args}, nil
}
