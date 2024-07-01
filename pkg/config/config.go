package config

// Config represents the configs model.
type Config struct {
	// Application is the model of application configs.
	Application struct {
		// Name of the application.
		Name string `yaml:"name"`
		// PProf is a flag to enable/disable profiling.
		PProf bool `yaml:"pprof"`
		// PublicAddr is the public address of the application, example: https://application.com
		PublicAddr string `yaml:"public_addr"`
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

	// OAuthGoogle holds Google's oauth configs.
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
