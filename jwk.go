package xssec

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"time"
)

var (
	ErrNoJKUInHeader  = errors.New("no jku in header available to validate trust")
	ErrJKUNotValid    = errors.New("jku is not valid")
	ErrKIDInvalidType = errors.New("expecting JWT header to have string kid")
)

// JWKFetcher defines a function type for fetching JSON Web Key Sets (JWKS) from a given URL and key ID.
type JWKFetcher func(jkuURL string, keyID string) (jwk.Set, error)

// NewNoCacheJWKFetcher creates a JWKFetcher that directly fetches JWKS from a given URL without caching
// It establishes a context with a timeout for the HTTP request to ensure it does not hang indefinitely
//
// :param timeoutOpts: Optional timeout options for the context. Default is 10 seconds.
//
// :return: JWKFetcher function
func NewNoCacheJWKFetcher(timeoutOpts ...time.Duration) JWKFetcher {
	timeout := 10 * time.Second
	if len(timeoutOpts) > 0 {
		timeout = timeoutOpts[0]
	}
	return func(jkuURL string, keyID string) (jwk.Set, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		jwkSet, err := jwk.Fetch(ctx, jkuURL)
		if err != nil {
			return nil, errors.New("failed to fetch public JWKS")
		}
		return jwkSet, nil
	}
}

// NewCachedJWKFetcher creates a JWKFetcher that attempts to fetch JWKs from a cache before falling back to a direct fetch
// It takes two function parameters: cacheGetter for retrieving JWKs from cache and cacheSetter for updating the cache
//
// :param cacheGetter: Function to retrieve JWKs from cache
// :param cacheSetter: Function to update the cache
//
// :return: JWKFetcher function
func NewCachedJWKFetcher(
	cacheGetter func(key string) (jwk.Set, bool),
	cacheSetter func(key string, value jwk.Set),
) JWKFetcher {
	directFetcher := NewNoCacheJWKFetcher()
	return func(jkuURL string, keyID string) (jwk.Set, error) {
		cacheKey := fmt.Sprintf("jwks_%s_%s", jkuURL, keyID)

		if jwks, found := cacheGetter(cacheKey); found {
			return jwks, nil
		}

		jwkSet, err := directFetcher(jkuURL, keyID)
		if err != nil {
			return nil, err
		}

		cacheSetter(cacheKey, jwkSet)
		return jwkSet, nil
	}
}

// JWTKeyResolver creates a jwt.Keyfunc using the given domain and JWKFetcher to resolve signing keys for JWT validation
// It requires a domain to match the JKU (JWK Set URL) and a function to validate the JKU
//
// :param domain: The domain to match the JKU
// :param validateJKU: Function to validate the JKU
// :param fetchJWK: Function to fetch the JWK Set from a given URL and key ID
//
// :return: jwt.Keyfunc function
func JWTKeyResolver(uaaDomain string, validateJKU JKUValidationFunc, fetchJWK JWKFetcher) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		jkuURL, keyID, err := extractJKUAndKeyID(token, validateJKU, uaaDomain)
		if err != nil {
			return nil, err
		}

		jwkSet, err := fetchJWK(jkuURL, keyID)
		if err != nil {
			return nil, err
		}

		key, ok := jwkSet.LookupKeyID(keyID)
		if !ok {
			return nil, fmt.Errorf("unable to find key %q", keyID)
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, err
		}
		return rawKey, nil
	}
}

// extractJKUAndKeyID extracts the JKU and Key ID from the JWT token header and validates the JKU
//
// :param token: The JWT token to extract the JKU and Key ID from
// :param validateJKU: Function to validate the JKU
// :param uaaDomain: The domain to match the JKU
//
// :return: The JKU URL and Key ID extracted from the JWT token header
func extractJKUAndKeyID(
	token *jwt.Token,
	validateJKU JKUValidationFunc,
	uaaDomain string,
) (string, string, error) {
	if token.Header["jku"] == nil {
		return "", "", ErrNoJKUInHeader
	}
	jkuUrl := token.Header["jku"].(string)
	if jkuUrl == "" {
		return "", "", ErrNoJKUInHeader
	}

	// validate JKU
	if isValid, err := validateJKU(jkuUrl, uaaDomain); err != nil {
		return "", "", err
	} else if !isValid {
		return "", "", ErrJKUNotValid
	}

	if token.Header["kid"] == nil {
		return "", "", ErrKIDInvalidType
	}
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return "", "", ErrKIDInvalidType
	}
	return jkuUrl, keyID, nil
}
