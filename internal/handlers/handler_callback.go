package handlers

import (
	"net/http"
)

// Callback handles the provider's callback and then finally redirects back to the client's callback URI.
func (h Handler) Callback(w http.ResponseWriter, r *http.Request) {}
