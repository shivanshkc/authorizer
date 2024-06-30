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
}

// Load loads and returns the config value.
func Load() *Config {
	return loadWithViper()
}

// LoadMock provides a mock instance of the config for testing purposes.
func LoadMock() *Config {
	cfg := &Config{}

	cfg.Application.Name = "example-application"
	cfg.HTTPServer.Addr = "localhost:8080"

	cfg.Logger.Level = "debug"
	cfg.Logger.Pretty = true

	return cfg
}
