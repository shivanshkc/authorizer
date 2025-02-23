package oauth

import (
	"net/url"
)

// mustParseURL parses the given string as a URL. It panics upon error.
//
// Ideally, this function would be in a dedicated utility package for more reusability, but it's not because I don't
// want the oauth package to have any dependencies over other local packages.
func mustParseURL(u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		panic("error in url.Parse call: " + err.Error())
	}
	return parsed
}
