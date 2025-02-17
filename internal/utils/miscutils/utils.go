package miscutils

import (
	"net/url"
)

// MustParseURL parses the given string as a URL. It panics upon error.
func MustParseURL(u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		panic("error in url.Parse call: " + err.Error())
	}
	return parsed
}
