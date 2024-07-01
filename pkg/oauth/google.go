package oauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/shivanshkc/authorizer/internal/database"
	"github.com/shivanshkc/authorizer/pkg/config"
)

// GoogleProvider implements the Provider interface for Google.
type GoogleProvider struct {
	Config     config.Config
	httpClient *http.Client
}

// NewGoogleProvider returns a new Google OAuth Provider instance.
func NewGoogleProvider(conf config.Config) *GoogleProvider {
	return &GoogleProvider{Config: conf, httpClient: &http.Client{}}
}

func (g *GoogleProvider) Name() string {
	return "google"
}

func (g *GoogleProvider) GetRedirectURL(ctx context.Context, state string) string {
	conf := g.Config.OAuthGoogle
	publicAddr := g.Config.Application.PublicAddr

	return fmt.Sprintf(
		"%s?scope=%s&include_granted_scopes=true&response_type=code&redirect_uri=%s&client_id=%s&state=%s",
		conf.RedirectURI,
		conf.Scopes,
		fmt.Sprintf("%s/api/auth/%s/callback", publicAddr, g.Name()),
		conf.ClientID,
		state,
	)
}

func (g *GoogleProvider) TokenFromCode(ctx context.Context, code string) (string, error) {
	panic("implement me")
}

func (g *GoogleProvider) UserFromToken(ctx context.Context, token string) (database.UserDoc, error) {
	panic("implement me")
}
