package config

// Config represents the configs model.
type Config struct {
	// Application is the model of application configs.
	Application struct {
		// Name of the application.
		Name string `yaml:"name"`
		// BaseURL of the application.
		// It can be http://localhost:8080 during development and https://domain.com in production.
		BaseURL string `yaml:"base_url"`
	} `yaml:"application"`

	Database struct {
		Addr     string `yaml:"addr"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Database string `yaml:"database"`
	} `yaml:"database"`

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

	// AllowedRedirectURLs is the list of URLs that Authorizer may redirect to after th OAuth flow is complete.
	AllowedRedirectURLs []string `yaml:"allowed_redirect_urls"`

	// Google OAuth related configs.
	Google struct {
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
	} `yaml:"google"`
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
