package xssec

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestConfig_Validate tests the Validate function
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name: "valid configuration",
			config: Config{
				ClientID:  "client123",
				XSAppName: "myapp",
				URL:       "https://service.xsuaa.example.com",
				UAADomain: "uaa.example.com",
			},
			wantErr: nil,
		},
		{
			name: "missing ClientID",
			config: Config{
				XSAppName: "myapp",
				URL:       "https://service.xsuaa.example.com",
				UAADomain: "uaa.example.com",
			},
			wantErr: ErrMissingClientID,
		},
		{
			name: "missing XSAppName",
			config: Config{
				ClientID:  "client123",
				URL:       "https://service.xsuaa.example.com",
				UAADomain: "uaa.example.com",
			},
			wantErr: ErrMissingXSAppName,
		},
		{
			name: "missing URL",
			config: Config{
				ClientID:  "client123",
				XSAppName: "myapp",
				UAADomain: "uaa.example.com",
			},
			wantErr: ErrMissingURL,
		},
		{
			name: "missing UAADomain",
			config: Config{
				ClientID:  "client123",
				XSAppName: "myapp",
				URL:       "https://service.xsuaa.example.com",
			},
			wantErr: ErrMissingUAADomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.Equal(t, tt.wantErr, err)
		})
	}
}
