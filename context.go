package xssec

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var (
	ErrInvalidClaims = errors.New("could not convert claims to SecurityContext")
)

const AppNamePrefix = "$XSAPPNAME."

type JKUValidationFunc func(jkuUrl, uaaDomain string) (bool, error)

type JWTValidationFunc func(decodedToken *jwt.Token, clientId, xsAppName string) (bool, error)

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

// securityContextConfig is a struct for specifying configuration options.
type securityContextConfig struct {
	// ValidationKeyGetter is the function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc

	// JKUValidator is a function to Validate JKU
	JKUValidator JKUValidationFunc

	// AudienceValidator is a function to make xsuaa specific audience and clientId checks
	AudienceValidator JWTValidationFunc
}

var defaultSecurityContextConfig = securityContextConfig{
	AudienceValidator: ValidateJWTTokenAudiences,
	JKUValidator:      ValidateJKU,
}

type SecurityContextOption func(*securityContextConfig)

// WithValidationKeyGetter is an option to set the KeyGetter function for the JWT
func WithValidationKeyGetter(keyGetter jwt.Keyfunc) SecurityContextOption {
	return func(o *securityContextConfig) {
		o.ValidationKeyGetter = keyGetter
	}
}

// WithJKUValidator is an option to set the ValidateJKU function for the JWT
func WithJKUValidator(jkuValidator JKUValidationFunc) SecurityContextOption {
	return func(o *securityContextConfig) {
		o.JKUValidator = jkuValidator
	}
}

// WithAudienceValidator is an option to set the AudienceValidator function for the JWT
func WithAudienceValidator(audienceValidator JWTValidationFunc) SecurityContextOption {
	return func(o *securityContextConfig) {
		o.AudienceValidator = audienceValidator
	}
}

// NewSecurityContext creates a new SecurityContext from a raw JWT token and a Config
// It will validate the token and check for the correct audience and clientID
// By default it won't use any cache for the JWKs
//
// :param rawToken: the raw JWT token
// :param config: the xsuaa config
// :param options: additional options to configure the SecurityContext
//
// :return: a new SecurityContext or an error
func NewSecurityContext(rawToken string, config *Config, options ...SecurityContextOption) (*SecurityContext, error) {
	// check if config is valid
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// create config and apply options
	conf := defaultSecurityContextConfig
	for _, o := range options {
		o(&conf)
	}

	// set default ValidationKeyGetter if not set
	// by default, no cache is used
	if conf.ValidationKeyGetter == nil {
		conf.ValidationKeyGetter = JWTKeyResolver(config.UAADomain, conf.JKUValidator, NewNoCacheJWKFetcher())
	}

	// decode and verify token with KeyFunc
	decodedToken, err := jwt.ParseWithClaims(
		rawToken,
		new(SecurityContext),
		conf.ValidationKeyGetter,
		/* jwt.WithoutAudienceValidation(), */
		jwt.WithLeeway(1*time.Minute),
	)
	if err != nil {
		return nil, err
	}

	// use xsuaa specific checks to assure domain validity
	if _, err = conf.AudienceValidator(decodedToken, config.ClientID, config.XSAppName); err != nil {
		return nil, err
	}

	claims, ok := decodedToken.Claims.(*SecurityContext)
	if !ok {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}
