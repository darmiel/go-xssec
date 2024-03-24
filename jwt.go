package xssec

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

var (
	// ErrNoClientID indicates a missing client ID
	ErrNoClientID = errors.New("client ID is required but not provided")

	// ErrInvalidClientID indicates an invalid client ID
	ErrInvalidClientID = errors.New("client ID is invalid")

	// ErrClientIDMismatch indicates a client ID mismatch
	ErrClientIDMismatch = errors.New("client ID mismatch")

	// ErrNoClientIDInToken indicates a missing client ID within the token
	ErrNoClientIDInToken = errors.New("client ID is required in the token but not found")

	// ErrNoScopeInToken indicates a missing scope within the token
	ErrNoScopeInToken = errors.New("scope is required in the token but not found")

	// ErrNoAudienceInToken indicates a missing audience within the token
	ErrNoAudienceInToken = errors.New("audience is required in the token but not found")

	// ErrInvalidTokenClaimsFormat indicates an invalid token claims format
	ErrInvalidTokenClaimsFormat = errors.New("invalid token claims format")
)

// ValidateJWTTokenAudiences checks if the JWT token adheres to XSUAA specific rules, primarily verifying the audience
// against the configured clientId and xsAppName from the XSUAA binding
//
// :param token: The JWT token to validate
// :param clientID: The client ID to validate against
// :param xsAppName: The XS application name to validate against
//
// :return: true if the token is valid, false otherwise
func ValidateJWTTokenAudiences(token *jwt.Token, configClientID, xsAppName string) (bool, error) {
	if configClientID == "" {
		return false, ErrNoClientID
	}
	claims, ok := token.Claims.(*SecurityContext)
	if !ok {
		return false, ErrInvalidTokenClaimsFormat
	}
	if claims.ClientID == "" {
		return false, ErrNoClientIDInToken
	}
	if len(claims.Scopes) == 0 {
		return false, ErrNoScopeInToken
	}
	if len(claims.Audience) == 0 {
		return false, ErrNoAudienceInToken
	}
	return validateAudiences(claims.Audience, claims.Scopes, claims.ClientID, configClientID, xsAppName)
}

// validateAudiences checks if the provided audiences and scopes from the token are valid for the given clientID and xsAppName
// It returns true if the token is valid, otherwise an error is returned
//
// :param audiences: The audiences from the token
// :param scopes: The scopes from the token
// :param cid: The client ID from the token
// :param clientID: The client ID to validate against
// :param xsAppName: The XS application name to validate against
//
// :return: true if the token is valid, false otherwise
func validateAudiences(tokenAudiences, tokenScopes []string, tokenClientID, configClientID, xsAppName string) (bool, error) {
	allowedAudiences := extractAudienceValues(tokenAudiences, tokenScopes, tokenClientID)

	clientIdentifiers := []string{configClientID}
	if xsAppName != "" {
		clientIdentifiers = append(clientIdentifiers, xsAppName)
	}

	if !isValidClientID(tokenClientID, configClientID) {
		return false, ErrClientIDMismatch
	}

	if isValidAudienceForBroker(clientIdentifiers, allowedAudiences) ||
		isDefaultAudienceValid(clientIdentifiers, allowedAudiences) {
		return true, nil
	}

	return false, fmt.Errorf("JWT token with audience: %v is not issued for these clientIds: %v", allowedAudiences, clientIdentifiers)
}

// extractAudienceValues generates a list of audience strings from token audiences, scopes, and cid
//
// :param audiences: The audiences from the token
// :param scopes: The scopes from the token
// :param cid: The client ID from the token
//
// :return: A list of unique audience values
func extractAudienceValues(audiences, scopes []string, cid string) []string {
	audienceSet := make(map[string]struct{})
	for _, aud := range audiences {
		if dotIndex := strings.Index(aud, "."); dotIndex > -1 {
			aud = strings.TrimSpace(aud[:dotIndex])
		}
		audienceSet[aud] = struct{}{}
	}

	for _, scope := range scopes {
		if dotIndex := strings.Index(scope, "."); dotIndex > -1 {
			aud := strings.TrimSpace(scope[:dotIndex])
			audienceSet[aud] = struct{}{}
		}
	}

	if cid != "" {
		audienceSet[cid] = struct{}{}
	}

	var result []string
	for aud := range audienceSet {
		result = append(result, aud)
	}
	return result
}

// isValidClientID checks if the client ID from the token matches the expected client ID
//
// :param cidFromToken: The client ID from the token
// :param expectedCID: The expected client ID
//
// :return: true if the client ID is valid, false otherwise
func isValidClientID(cidFromToken, expectedCID string) bool {
	if cidFromToken == "" {
		return false
	}
	return strings.TrimSpace(cidFromToken) == strings.TrimSpace(expectedCID)
}

// isValidAudienceForBroker checks if the audiences for a XSUAA broker clone are valid
//
// :param clientIDs: The client IDs to check
// :param allowedAudiences: The allowed audiences
//
// :return: true if the audience is valid for a broker client, false otherwise
func isValidAudienceForBroker(clientIDs, allowedAudiences []string) bool {
	for _, clientID := range clientIDs {
		if strings.Contains(clientID, "!b") { // Check for broker client IDs.
			for _, audience := range allowedAudiences {
				if strings.HasSuffix(audience, "|"+clientID) {
					return true // Valid audience found for broker client.
				}
			}
		}
	}
	return false // No valid audience found for any broker clients.
}

// isDefaultAudienceValid checks if the default validation passes by comparing allowed audiences with client IDs
//
// :param clientIDs: The client IDs to check
// :param allowedAudiences: The allowed audiences
//
// :return: true if the default audience is valid, false otherwise
func isDefaultAudienceValid(clientIDs, allowedAudiences []string) bool {
	audienceSet := make(map[string]struct{})
	for _, aud := range allowedAudiences {
		audienceSet[aud] = struct{}{}
	}

	for _, clientID := range clientIDs {
		if _, exists := audienceSet[clientID]; exists {
			return true // Client ID is within the allowed audiences.
		}
	}
	return false // No client ID matches the allowed audiences.
}

// interfaceSliceToStringSlice converts a slice of interfaces to a slice of strings
//
// :param input: The slice of interfaces to convert
//
// :return: The converted slice of strings
func interfaceSliceToStringSlice(input []interface{}) []string {
	var output []string
	for _, v := range input {
		output = append(output, v.(string))
	}
	return output
}
