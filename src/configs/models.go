package configs

// Model represents the configs model.
type Model struct {
	// Application is the model of application configs.
	Application struct {
		// Name of the application.
		Name string `yaml:"name"`
	} `yaml:"application"`

	// HTTPServer is the model of the HTTP Server configs.
	HTTPServer struct {
		// Addr is the address of the HTTP server.
		Addr string `yaml:"addr"`
	} `yaml:"http_server"`

	// Mongo is the model of the MongoDB configs.
	Mongo struct {
		// Addr of the MongoDB deployment.
		Addr string `yaml:"addr"`
		// OperationTimeoutSec is the timeout in seconds for any MongoDB operation.
		OperationTimeoutSec int `yaml:"operation_timeout_sec"`
		// DatabaseName is the name of the logical database in MongoDB.
		DatabaseName string `yaml:"database_name"`
	} `yaml:"mongo"`

	// OAuthGeneral holds the general OAuth configs.
	OAuthGeneral struct {
		// ClientCallbackURL is where the frontend will receive the OAuth result.
		ClientCallbackURL string `yaml:"client_callback_url"`
		// ServerCallbackURL is where the service receives oauth callbacks from providers.
		ServerCallbackURL string `yaml:"server_callback_url"`
	} `yaml:"oauth_general"`
}
