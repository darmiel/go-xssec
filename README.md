# go-xssec

go-xssec is a (more or less maintained) fork of 
[cloud-security-client-golang-xsuaa](https://github.com/SAP-archive/cloud-security-client-golang-xsuaa).
It allows you to easily integrate XSUAA security services into your Go applications.

## Installation

To use this library in your project, install it using `go get`:

```bash
go get -u github.com/darmiel/go-xssec
```

## Basic Usage

Below is a basic example of how to use the library to create a security context from a JWT token:

```go
package main

import (
	"github.com/darmiel/go-xssec"
)

func main() {
	config := xssec.Config{
        // Your service binding client ID
		ClientID: "sb-app!t000000",
        
        // Your XS application name
		XSAppName: "app!t000000",
        
        // The XSUAA service URL
		URL: "https://my-app.authentication.eu12.hana.ondemand.com",
        
        // The UAA domain of your XSUAA service
		UAADomain: "authentication.eu12.hana.ondemand.com",
	}

	// Replace the token with a valid JWT token
	rawToken := "YOUR_JWT_TOKEN"

	ctx, err := xssec.NewSecurityContext(rawToken, &config)
	if err != nil {
		panic(err)
	}
}
```

You can then use the `SecurityContext` object to access the user's attributes and scopes:

```go
type SecurityContext struct {
	jwt.RegisteredClaims
	AuthTime            int                // Time of authentication.
	AuthorizedParty     string             // Authorized party to which the token was issued.
	ClientID            string             // Client identifier.
	Email               string             // User's email address.
	ExternalAttributes  ExternalAttributes // External attributes associated with the user.
	FamilyName          string             // User's family name.
	GivenName           string             // User's given name.
	GrantType           string             // Type of grant.
	Origin              string             // Origin of the token.
	RevocationSignature string             // Revocation signature.
	Scopes              []string           // Scopes granted to the token.
	UserID              string             // User's identifier.
	UserName            string             // User's name.
	UserUUID            string             // User's UUID.
	XsSystemAttributes  XsSystemAttributes // XS system attributes.
	XsUserAttributes    struct{}           // XS user attributes (empty for future use).
	TenantID            string             // Tenant identifier.
}
```