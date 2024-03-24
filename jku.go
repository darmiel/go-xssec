package xssec

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	// ErrURLNotParsable indicates that the provided URL could not be parsed.
	ErrURLNotParsable = errors.New("URL not parsable within the header")

	// ErrJKUDomainMismatch indicates a mismatch between the JKU URL's domain and the expected UAA domain.
	ErrJKUDomainMismatch = errors.New("JKU of the JWT token does not match with the UAA domain. Use legacy-token-key")
)

// ValidateJKU checks if the JKU URL's hostname matches the expected UAA domain, ensuring the service is correctly configured.
// It returns true if the JKU URL domain matches the expected UAA domain, otherwise an error is returned.
func ValidateJKU(jkuURL, uaaDomain string) (bool, error) {
	if uaaDomain == "" {
		return false, ErrMissingUAADomain
	}

	parsedURL, err := url.Parse(jkuURL)
	if err != nil {
		return false, ErrURLNotParsable
	}

	hostname := parsedURL.Hostname()
	if !strings.Contains(hostname, uaaDomain) {
		return false, fmt.Errorf("%w: JKU ('%s') does not match UAA domain ('%s')", ErrJKUDomainMismatch, jkuURL, uaaDomain)
	}

	return true, nil
}
