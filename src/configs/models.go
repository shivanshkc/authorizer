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
		// ServerCallbackURL is where the service receives oauth callbacks from providers.
		ServerCallbackURL string `yaml:"server_callback_url"`
	} `yaml:"oauth_general"`

	// OAuthGoogle holds Google's oauth configs.
	OAuthGoogle struct {
		// RedirectURL is the authentication URL where the users are redirected.
		RedirectURL string `yaml:"redirect_url"`
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
