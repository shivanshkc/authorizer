package config

// Config represents the configs model.
type Config struct {
	// Application is the model of application configs.
	Application struct {
		// Name of the application.
		Name string `yaml:"name"`
		// PProf is a flag to enable/disable profiling.
		PProf bool `yaml:"pprof"`
	} `yaml:"application"`

	// HTTPServer is the model of the HTTP Server configs.
	HTTPServer struct {
		// Addr is the address of the HTTP server.
		Addr string `yaml:"addr"`
	} `yaml:"http_server"`

	// Logger is the model of the application logger configs.
	Logger struct {
		// Level of the logger.
		Level string `yaml:"level"`
		// Pretty is a flag that dictates whether the log output should be pretty (human-readable).
		Pretty bool `yaml:"pretty"`
	} `yaml:"logger"`

	// Mongo is the model of the MongoDB configs.
	Mongo struct {
		// Addr of the MongoDB deployment.
		Addr string `yaml:"addr"`
		// DatabaseName is the name of the logical database in MongoDB.
		DatabaseName string `yaml:"database_name"`
	} `yaml:"mongo"`

	// OAuthGeneral holds general oauth configs.
	OAuthGeneral struct {
		// ServerRedirectURI is the address of the application for provider's callback.
		ServerRedirectURI string `yaml:"server_redirect_uri"`
		// AllowedClientRedirectURIs is the list of allowed client redirect URIs.
		AllowedClientRedirectURIs []string `yaml:"allowed_client_redirect_uris"`
	} `yaml:"oauth_general"`

	// OAuthGoogle holds Google specific oauth configs.
	OAuthGoogle struct {
		// RedirectURI is the URL of Google's authentication page.
		RedirectURI string `yaml:"redirect_uri"`
		// Scopes are the OAuth scopes.
		Scopes string `yaml:"scopes"`
		// ClientID is the OAuth client ID.
		ClientID string `yaml:"client_id"`
		// ClientSecret is the OAuth client secret.
		ClientSecret string `yaml:"client_secret"`
		// TokenEndpoint is Google's endpoint to exchange OAuth-code with ID token.
		TokenEndpoint string `yaml:"token_endpoint"`
	} `yaml:"oauth_google"`
}

// Load loads and returns the config value.
func Load() Config {
	return loadWithViper()
}

// LoadMock provides a mock instance of the config for testing purposes.
func LoadMock() Config {
	cfg := Config{}

	cfg.Application.Name = "example-application"
	cfg.HTTPServer.Addr = "localhost:8080"

	cfg.Logger.Level = "debug"
	cfg.Logger.Pretty = true

	return cfg
}
