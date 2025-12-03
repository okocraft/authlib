package user_test

import (
	"testing"

	"github.com/okocraft/auth-service/user"
	"github.com/stretchr/testify/assert"
)

func TestID_String(t *testing.T) {
	tests := []struct {
		name string
		id   user.ID
		want string
	}{
		{
			name: "1",
			id:   user.ID(1),
			want: "1",
		},
		{
			name: "zero",
			id:   user.ID(0),
			want: "0",
		},
		{
			name: "-1",
			id:   user.ID(-1),
			want: "-1",
		},
		{
			name: "unspecified (zero value)",
			want: "0",
		},
		{
			name: "min",
			id:   user.ID(-2147483648), // math.MinInt32
			want: "-2147483648",
		},
		{
			name: "max",
			id:   user.ID(2147483647), // math.MaxInt32
			want: "2147483647",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.id.String())
		})
	}
}
