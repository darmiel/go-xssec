package xssec

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestExtractJKUAndKeyID tests the extractJKUAndKeyID function
func TestExtractJKUAndKeyID(t *testing.T) {
	t.Run("error when jku is missing", func(t *testing.T) {
		token := &jwt.Token{Header: map[string]interface{}{}}
		jku, kid, err := extractJKUAndKeyID(token, nil, "")
		assert.Empty(t, jku)
		assert.Empty(t, kid)
		assert.Equal(t, ErrNoJKUInHeader, err)
	})

	t.Run("error when jku is empty", func(t *testing.T) {
		token := &jwt.Token{Header: map[string]interface{}{"jku": ""}}
		jku, kid, err := extractJKUAndKeyID(token, nil, "")
		assert.Empty(t, jku)
		assert.Empty(t, kid)
		assert.Equal(t, ErrNoJKUInHeader, err)
	})

	t.Run("error from jku validation", func(t *testing.T) {
		token := &jwt.Token{Header: map[string]interface{}{"jku": "https://example.com"}}
		mockErr := errors.New("mock error")
		jku, kid, err := extractJKUAndKeyID(token, func(jkuUrl, uaaDomain string) (bool, error) {
			return false, mockErr
		}, "")
		assert.Empty(t, jku)
		assert.Empty(t, kid)
		assert.Equal(t, mockErr, err)
	})

	t.Run("jku validation fails", func(t *testing.T) {
		token := &jwt.Token{Header: map[string]interface{}{"jku": "https://example.com"}}
		jku, kid, err := extractJKUAndKeyID(token, func(jkuUrl, uaaDomain string) (bool, error) {
			return false, nil
		}, "")
		assert.Empty(t, jku)
		assert.Empty(t, kid)
		assert.Equal(t, ErrJKUNotValid, err)
	})

	t.Run("kid missing", func(t *testing.T) {
		token := &jwt.Token{Header: map[string]interface{}{"jku": "https://example.com"}}
		jku, kid, err := extractJKUAndKeyID(token, func(jkuUrl, uaaDomain string) (bool, error) {
			return true, nil
		}, "")
		assert.Empty(t, jku)
		assert.Empty(t, kid)
		assert.Equal(t, ErrKIDInvalidType, err)
	})

	t.Run("kid invalid type", func(t *testing.T) {
		token := &jwt.Token{Header: map[string]interface{}{"jku": "https://example.com", "kid": 123}}
		jku, kid, err := extractJKUAndKeyID(token, func(jkuUrl, uaaDomain string) (bool, error) {
			return true, nil
		}, "")
		assert.Empty(t, jku)
		assert.Empty(t, kid)
		assert.Equal(t, ErrKIDInvalidType, err)
	})

	t.Run("success", func(t *testing.T) {
		expectedJKU := "https://example.com"
		expectedKID := "keyID"
		token := &jwt.Token{Header: map[string]interface{}{"jku": expectedJKU, "kid": expectedKID}}
		jku, kid, err := extractJKUAndKeyID(token, func(jkuUrl, uaaDomain string) (bool, error) {
			return true, nil
		}, "")
		assert.Equal(t, expectedJKU, jku)
		assert.Equal(t, expectedKID, kid)
		assert.NoError(t, err)
	})
}
