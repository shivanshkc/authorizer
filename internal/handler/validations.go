package handler

import (
	"errors"
	"net/url"
	"regexp"
)

var (
	errInvalidProvider = errors.New("provider must be upto 20 characters and must include only a-z, 0-9, - and _")
	errInvalidCCU      = errors.New("redirect_url must be present, must be upto 200 characters and a valid url")
)

var (
	providerRegex = regexp.MustCompile(`^[a-z0-9_-]+$`)
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
