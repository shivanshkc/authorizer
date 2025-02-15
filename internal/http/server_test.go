package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/logger"
	"github.com/shivanshkc/authorizer/internal/middleware"
)

// TestServer_Start checks if the HTTP server starts correctly with all the valid parameters.
func TestServer_Start(t *testing.T) {
	// Start the server with mock dependencies.
	server := mockServerStart()
	defer func() { _ = server.httpServer.Shutdown(context.Background()) }()

	// Server dependencies.
	cfg := config.LoadMock()

	// Dummy request with a path that does not exist. We will expect 404.
	reqURI := fmt.Sprintf("http://%s/not-existent-path", cfg.HTTPServer.Addr)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURI, nil)

	// Execute request.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Errorf("unexpected error in http request execution: %v", err)
		return
	}

	// Cleanup.
	defer func() { _ = resp.Body.Close() }()

	// Verify status code.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status code to be: %d, but got: %d", http.StatusNotFound, resp.StatusCode)
		return
	}
}

// mockServerStart creates a *Server instance using a mock logger.
// It sleeps for a second to give the server some time to boot up.
func mockServerStart() *Server {
	// Server dependencies.
	conf := config.LoadMock()
	logger.Init(io.Discard, conf.Logger.Level, conf.Logger.Pretty)

	// Instantiate the server to be tested.
	server := &Server{
		Config:     conf,
		Middleware: middleware.Middleware{},
	}

	// Start the server without blocking.
	go func() { _ = server.Start() }()

	// Wait for the server to start.
	time.Sleep(time.Second)
	return server
}
