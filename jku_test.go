package xssec

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidateJKU(t *testing.T) {
	cases := []struct {
		name       string
		jkuURL     string
		uaaDomain  string
		want       bool
		wantErr    error
		errMessage string
	}{
		{
			name:      "empty UAA domain",
			jkuURL:    "https://example.com",
			uaaDomain: "",
			want:      false,
			wantErr:   ErrMissingUAADomain,
		},
		{
			name:      "invalid URL",
			jkuURL:    "://",
			uaaDomain: "example.com",
			want:      false,
			wantErr:   ErrURLNotParsable,
		},
		{
			name:       "domain mismatch",
			jkuURL:     "https://wrong.com",
			uaaDomain:  "example.com",
			want:       false,
			wantErr:    ErrJKUDomainMismatch,
			errMessage: "JKU of the JWT token does not match with the UAA domain. Use legacy-token-key: JKU ('https://wrong.com') does not match UAA domain ('example.com')",
		},
		{
			name:      "valid case",
			jkuURL:    "https://subdomain.example.com",
			uaaDomain: "example.com",
			want:      true,
			wantErr:   nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateJKU(tt.jkuURL, tt.uaaDomain)
			if tt.wantErr != nil {
				require.Error(t, err)
				if tt.errMessage != "" {
					require.EqualError(t, err, tt.errMessage)
				} else {
					require.ErrorIs(t, err, tt.wantErr)
				}
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
