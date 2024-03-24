package xssec

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

// Config defines the configuration required for XSUAA service integration.
// It includes the client ID, XS application name, service URL, and UAA domain.
type Config struct {
	ClientID  string // ClientID represents the OAuth client identifier.
	XSAppName string // XSAppName represents the XS application name for service bindings.
	URL       string // URL is the endpoint of the XSUAA service.
	UAADomain string // UAADomain is the domain of the UAA service.
}

var (
	// ErrMissingClientID indicates the absence of a client ID in the configuration.
	ErrMissingClientID = errors.New("missing ClientID in configuration")
	// ErrMissingXSAppName indicates the absence of an XS application name in the configuration.
	ErrMissingXSAppName = errors.New("missing XSAppName in configuration")
	// ErrMissingURL indicates the absence of a service URL in the configuration.
	ErrMissingURL = errors.New("missing URL in configuration")
	// ErrMissingUAADomain indicates the absence of a UAA domain in the configuration.
	ErrMissingUAADomain = errors.New("missing UAADomain in configuration")
)

// Validate checks the Config instance for completeness, ensuring that all necessary
// fields are provided. It returns an error if any field is missing.
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return ErrMissingClientID
	}
	if c.XSAppName == "" {
		return ErrMissingXSAppName
	}
	if c.URL == "" {
		return ErrMissingURL
	}
	if c.UAADomain == "" {
		return ErrMissingUAADomain
	}
	return nil
}

// SecurityContext holds authentication and authorization details for a user session.
type SecurityContext struct {
	jwt.RegisteredClaims
	AuthTime        int    `json:"auth_time"` // Time of authentication.
	AuthorizedParty string `json:"azp"`       // Authorized party to which the token was issued.
	ClientID        string `json:"cid"`       // Client identifier.
	// XsClientID          string             `json:"client_id"`            // I don't know, something xs related ig
	Email               string             `json:"email"`                // User's email address.
	ExternalAttributes  ExternalAttributes `json:"ext_attr"`             // External attributes associated with the user.
	FamilyName          string             `json:"family_name"`          // User's family name.
	GivenName           string             `json:"given_name"`           // User's given name.
	GrantType           string             `json:"grant_type"`           // Type of grant.
	Origin              string             `json:"origin"`               // Origin of the token.
	RevocationSignature string             `json:"rev_sig"`              // Revocation signature.
	Scopes              []string           `json:"scope"`                // Scopes granted to the token.
	UserID              string             `json:"user_id"`              // User's identifier.
	UserName            string             `json:"user_name"`            // User's name.
	UserUUID            string             `json:"user_uuid"`            // User's UUID.
	XsSystemAttributes  XsSystemAttributes `json:"xs.system.attributes"` // XS system attributes.
	XsUserAttributes    struct{}           `json:"xs.user.attributes"`   // XS user attributes (empty for future use).
	TenantID            string             `json:"zid"`                  // Tenant identifier.
}

// ExternalAttributes holds additional attributes associated with the user.
type ExternalAttributes struct {
	Enhancer     string `json:"enhancer"`
	SubAccountID string `json:"subaccountid"`
	ZDN          string `json:"zdn"`
}

// XsSystemAttributes holds system attributes for XS.
type XsSystemAttributes struct {
	XsRoleCollections []string `json:"xs.rolecollections"` // XS role collections.
}
