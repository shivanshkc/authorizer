package handler

import (
	"errors"
	"net/url"
	"regexp"

	"github.com/google/uuid"
)

var (
	errInvalidProvider = errors.New("provider must be upto 20 characters and must include only a-z, 0-9, - and _")
	errInvalidCCU      = errors.New("redirect_url must be present, must be upto 200 characters and a valid url")
	errInvalidState    = errors.New("state is malformed")
	errInvalidCode     = errors.New("code is malformed")
)

var (
	providerRegex = regexp.MustCompile(`^[a-z0-9_-]+$`)
	authCodeRegex = regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`)
)

// validateProvider validates the provider name parameter when received from an external user.
func validateProvider(p string) error {
	if len(p) == 0 || len(p) > 20 {
		return errInvalidProvider
	}

	if !providerRegex.MatchString(p) {
		return errInvalidProvider
	}

	return nil
}

// validateClientCallbackURL validates the client callback URL param (accepted as a query parameter named redirect_url).
func validateClientCallbackURL(u string) error {
	if len(u) == 0 || len(u) > 200 {
		return errInvalidCCU
	}

	if _, err := url.ParseRequestURI(u); err != nil {
		return errInvalidCCU
	}

	return nil
}

// validateState validates the "state" parameter returned by the oauth.Provider.
func validateState(s string) error {
	if _, err := uuid.Parse(s); err != nil {
		return errInvalidState
	}

	return nil
}

// validateAuthCode validates the "code" parameter returned by the oauth.Provider.
func validateAuthCode(code string) error {
	if len(code) == 0 || len(code) > 200 {
		return errInvalidCode
	}

	if !authCodeRegex.MatchString(code) {
		return errInvalidCode
	}

	return nil
}
