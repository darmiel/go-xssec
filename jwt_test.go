package xssec

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sort"
	"testing"
)

// TestExtractAudienceValues tests the extractAudienceValues function with various inputs.
func TestExtractAudienceValues(t *testing.T) {
	tests := []struct {
		name             string
		audiences        []string
		scopes           []string
		cid              string
		expectedAudience []string
	}{
		{
			name:             "No dot in audiences or scopes, non-empty cid",
			audiences:        []string{"aud1", "aud2"},
			scopes:           []string{"scope1", "scope2"},
			cid:              "client1",
			expectedAudience: []string{"aud1", "aud2", "client1"},
		},
		{
			name:             "Dot present in audiences and scopes, empty cid",
			audiences:        []string{"aud1.com", "aud2.org"},
			scopes:           []string{"scope1.com", "scope2.org"},
			cid:              "",
			expectedAudience: []string{"aud1", "aud2", "scope1", "scope2"},
		},
		{
			name:             "No dot in audiences, dot present in scopes, empty cid",
			audiences:        []string{"aud1.com", "aud2.org"},
			scopes:           []string{"scope1.com", "scope2"},
			cid:              "",
			expectedAudience: []string{"aud1", "aud2", "scope1"},
		},
		{
			name:             "Mixed cases with overlapping values",
			audiences:        []string{"aud1", "aud2.com"},
			scopes:           []string{"aud1", "scope2.org"},
			cid:              "aud1",
			expectedAudience: []string{"aud1", "aud2", "scope2"},
		},
		{
			name:             "Empty inputs",
			audiences:        []string{},
			scopes:           []string{},
			cid:              "",
			expectedAudience: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAudienceValues(tt.audiences, tt.scopes, tt.cid)
			sort.Strings(result) // Sort for comparison
			sort.Strings(tt.expectedAudience)

			assert.Equal(t, tt.expectedAudience, result)
		})
	}
}

// TestIsValidClientID tests the isValidClientID function with various inputs.
func TestIsValidClientID(t *testing.T) {
	tests := []struct {
		name          string
		cidFromToken  string
		expectedCID   string
		expectedValid bool
	}{
		{
			name:          "Exact match",
			cidFromToken:  "123456",
			expectedCID:   "123456",
			expectedValid: true,
		},
		{
			name:          "Mismatch",
			cidFromToken:  "123456",
			expectedCID:   "654321",
			expectedValid: false,
		},
		{
			name:          "Whitespace in token ID",
			cidFromToken:  " 123456 ",
			expectedCID:   "123456",
			expectedValid: true,
		},
		{
			name:          "Whitespace in expected ID",
			cidFromToken:  "123456",
			expectedCID:   " 123456 ",
			expectedValid: true,
		},
		{
			name:          "Whitespace in both IDs",
			cidFromToken:  " 123456 ",
			expectedCID:   " 123456 ",
			expectedValid: true,
		},
		{
			name:          "Empty strings",
			cidFromToken:  "",
			expectedCID:   "",
			expectedValid: false,
		},
		{
			name:          "Empty token ID",
			cidFromToken:  "",
			expectedCID:   "123456",
			expectedValid: false,
		},
		{
			name:          "Empty expected ID",
			cidFromToken:  "123456",
			expectedCID:   "",
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidClientID(tt.cidFromToken, tt.expectedCID)
			assert.Equal(t, tt.expectedValid, result)
		})
	}
}

// TestIsValidAudienceForBroker tests the isValidAudienceForBroker function with various inputs.
func TestIsValidAudienceForBroker(t *testing.T) {
	tests := []struct {
		name             string
		clientIDs        []string
		allowedAudiences []string
		expectedIsValid  bool
	}{
		{
			name:             "Valid audience with broker client ID",
			clientIDs:        []string{"123!b", "456"},
			allowedAudiences: []string{"xyz|123!b"},
			expectedIsValid:  true,
		},
		{
			name:             "No broker client ID in clientIDs",
			clientIDs:        []string{"123", "456"},
			allowedAudiences: []string{"xyz|123!b"},
			expectedIsValid:  false,
		},
		{
			name:             "Broker client ID does not match any allowed audiences",
			clientIDs:        []string{"123!b", "456!b"},
			allowedAudiences: []string{"xyz|789!b"},
			expectedIsValid:  false,
		},
		{
			name:             "Multiple client IDs with one valid broker client ID",
			clientIDs:        []string{"123!b", "456", "789!b"},
			allowedAudiences: []string{"xyz|789!b", "abc|123"},
			expectedIsValid:  true,
		},
		{
			name:             "Valid audience but without the broker client ID marker",
			clientIDs:        []string{"123", "456"},
			allowedAudiences: []string{"xyz|123", "abc|456"},
			expectedIsValid:  false,
		},
		{
			name:             "Empty clientIDs and allowedAudiences",
			clientIDs:        []string{},
			allowedAudiences: []string{},
			expectedIsValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidAudienceForBroker(tt.clientIDs, tt.allowedAudiences)
			assert.Equal(t, tt.expectedIsValid, result)
		})
	}
}

// TestIsDefaultAudienceValid tests the IsDefaultAudienceValid function with various inputs.
func TestIsDefaultAudienceValid(t *testing.T) {
	tests := []struct {
		name             string
		clientIDs        []string
		allowedAudiences []string
		expectedResult   bool
	}{
		{
			name:             "Valid single client ID",
			clientIDs:        []string{"client1"},
			allowedAudiences: []string{"client1", "client2"},
			expectedResult:   true,
		},
		{
			name:             "Multiple valid client IDs",
			clientIDs:        []string{"client1", "client3"},
			allowedAudiences: []string{"client1", "client2", "client3"},
			expectedResult:   true,
		},
		{
			name:             "No matching client IDs",
			clientIDs:        []string{"client4"},
			allowedAudiences: []string{"client1", "client2", "client3"},
			expectedResult:   false,
		},
		{
			name:             "Empty client IDs",
			clientIDs:        []string{},
			allowedAudiences: []string{"client1", "client2", "client3"},
			expectedResult:   false,
		},
		{
			name:             "Empty allowed audiences",
			clientIDs:        []string{"client1"},
			allowedAudiences: []string{},
			expectedResult:   false,
		},
		{
			name:             "Empty client IDs and allowed audiences",
			clientIDs:        []string{},
			allowedAudiences: []string{},
			expectedResult:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDefaultAudienceValid(tt.clientIDs, tt.allowedAudiences)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestValidateAudiences_ValidTokenWithClientID tests the validateAudiences function with a valid token containing a client ID.
func TestValidateAudiences_ValidTokenWithClientID(t *testing.T) {
	audiences := []string{"aud1", "aud2"}
	scopes := []string{"scope1", "scope2"}
	cid := "client123"
	clientID := "client123"
	xsAppName := ""

	valid, err := validateAudiences(audiences, scopes, cid, clientID, xsAppName)
	require.NoError(t, err)
	assert.True(t, valid)
}

// TestValidateAudiences_ValidTokenWithXsAppName tests the validateAudiences function with a valid token containing an XsAppName.
func TestValidateAudiences_ValidTokenWithXsAppName(t *testing.T) {
	audiences := []string{"aud1.xsappname"}
	scopes := []string{"scope1", "scope2.xsappname"}
	cid := "client123"
	clientID := "client123"
	xsAppName := "xsappname"

	valid, err := validateAudiences(audiences, scopes, cid, clientID, xsAppName)
	require.NoError(t, err)
	assert.True(t, valid)
}

// TestValidateAudiences_InvalidToken tests the validateAudiences function with an invalid token.
func TestValidateAudiences_InvalidToken(t *testing.T) {
	audiences := []string{"wrongaudience"}
	scopes := []string{"wrongscope"}
	cid := "client123"
	clientID := "client1234"
	xsAppName := "xsappname"

	valid, err := validateAudiences(audiences, scopes, cid, clientID, xsAppName)
	require.Error(t, err)
	assert.False(t, valid)
}

// TestValidateAudiences_ValidBrokerClientID tests the validateAudiences function with a valid broker client ID.
func TestValidateAudiences_ValidBrokerClientID(t *testing.T) {
	audiences := []string{"aud1|client123!b"}
	scopes := []string{"scope1", "scope2"}
	tokenClientID := "client123"
	configClientID := "client123"
	xsAppName := ""

	valid, err := validateAudiences(audiences, scopes, tokenClientID, configClientID, xsAppName)
	require.NoError(t, err)
	assert.True(t, valid)
}

// TestValidateAudiences_ValidDefaultAudience tests the validateAudiences function with a valid default audience.
func TestValidateAudiences_ValidDefaultAudience(t *testing.T) {
	audiences := []string{"client123"}
	scopes := []string{}
	cid := "client123"
	clientID := "client123"
	xsAppName := ""

	valid, err := validateAudiences(audiences, scopes, cid, clientID, xsAppName)
	require.NoError(t, err)
	assert.True(t, valid)
}

// TestValidateAudiences_InvalidCID tests the validateAudiences function with an invalid client ID.
func TestValidateAudiences_InvalidCID(t *testing.T) {
	audiences := []string{"aud1", "aud2"}
	scopes := []string{"scope1", "scope2"}
	cid := "wrongcid"
	clientID := "client123"
	xsAppName := ""

	valid, err := validateAudiences(audiences, scopes, cid, clientID, xsAppName)
	require.Error(t, err)
	assert.False(t, valid)
}

// TestValidateAudiences_EmptyClientIDAndXsAppName tests the validateAudiences function with an empty client ID and XsAppName.
func TestValidateAudiences_EmptyClientIDAndXsAppName(t *testing.T) {
	audiences := []string{"aud1", "aud2"}
	scopes := []string{"scope1", "scope2"}
	cid := "client123"
	clientID := ""
	xsAppName := ""

	valid, err := validateAudiences(audiences, scopes, cid, clientID, xsAppName)
	require.Error(t, err)
	assert.False(t, valid)
}

// TestValidateJWTToken tests the ValidateJWTToken function with various inputs.
func TestValidateJWTToken(t *testing.T) {
	var tests = []struct {
		name           string
		token          *jwt.Token
		xsAppName      string
		configClientID string
		want           bool
		wantErr        error
	}{
		{
			name: "valid token with clientID in audience",
			token: &jwt.Token{
				Claims: &SecurityContext{
					RegisteredClaims: jwt.RegisteredClaims{
						Audience: jwt.ClaimStrings{"openid", "sb-example!t123"},
					},
					Scopes:   []string{"read", "write"},
					ClientID: "sb-example!t123",
				},
			},
			configClientID: "sb-example!t123",
			xsAppName:      "example!t123",
			want:           true,
			wantErr:        nil,
		},
		{
			name: "valid token with xsAppName in audience",
			token: &jwt.Token{
				Claims: &SecurityContext{
					RegisteredClaims: jwt.RegisteredClaims{
						Audience: jwt.ClaimStrings{"openid", "example!t123"},
					},
					Scopes:   []string{"read", "write"},
					ClientID: "sb-example!t123",
				},
			},
			configClientID: "sb-example!t123",
			xsAppName:      "example!t123",
			want:           true,
			wantErr:        nil,
		},
		{
			name:           "missing config client id",
			token:          &jwt.Token{},
			configClientID: "",
			xsAppName:      "",
			want:           false,
			wantErr:        ErrNoClientID,
		},
		{
			name: "invalid claims format",
			token: &jwt.Token{
				Claims: jwt.MapClaims{},
			},
			configClientID: "a",
			xsAppName:      "",
			want:           false,
			wantErr:        ErrInvalidTokenClaimsFormat,
		},
		{
			name: "missing client in in claims",
			token: &jwt.Token{
				Claims: &SecurityContext{},
			},
			configClientID: "a",
			xsAppName:      "",
			want:           false,
			wantErr:        ErrNoClientIDInToken,
		},
		{
			name: "missing scopes in in claims",
			token: &jwt.Token{
				Claims: &SecurityContext{
					ClientID: "a",
				},
			},
			configClientID: "a",
			xsAppName:      "",
			want:           false,
			wantErr:        ErrNoScopeInToken,
		},
		{
			name: "missing audience in in claims",
			token: &jwt.Token{
				Claims: &SecurityContext{
					ClientID: "a",
					Scopes:   jwt.ClaimStrings{"a"},
				},
			},
			configClientID: "a",
			xsAppName:      "",
			want:           false,
			wantErr:        ErrNoAudienceInToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateJWTTokenAudiences(tt.token, tt.configClientID, tt.xsAppName)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateJWTTokenAudiences() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateJWTTokenAudiences() = %v, want %v", got, tt.want)
			}
		})
	}
}
