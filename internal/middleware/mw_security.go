package middleware

import (
	"net/http"
)

const (
	xContentTypeOptions = "X-Content-Type-Options"
	cacheControl        = "Cache-Control"
)

// Security adds essential security headers.
//
// NOTE: This middleware does not include headers like "Strict-Transport-Security", "X-Frame-Options",
// "Content-Security-Policy", "Referrer-Policy" etc. because they are better managed by a reverse proxy.
func (m Middleware) Security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers should not try to guess the Content-Type if it is not provided.
		// This mitigates the following vulnerabilities:
		// - Cross-site scripting (XSS) attacks through file uploads.
		// - Malicious code execution in trusted contexts.
		// - Information leakage across origins.
		w.Header().Set(xContentTypeOptions, "nosniff")

		// Prevent caching of sensitive data.
		// With this header, a malicious entity will not be able to use browser history or back button
		// to get access to any sensitive data.
		w.Header().Set(cacheControl, "no-store, max-age=0")

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
