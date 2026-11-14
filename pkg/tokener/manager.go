package tokener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Manager encapsulates methods required to create and manage access-refresh token pairs.
type Manager struct {
	issuer           string
	accessTokenLife  time.Duration
	refreshTokenLife time.Duration

	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey

	repo Repository
}

// NewManager returns a new instance of the manager.
func NewManager(
	issuer string, accessTokenLife, refreshTokenLife time.Duration,
	rawPublicKey, rawPrivateKey string, repo Repository,
) (*Manager, error) {
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), []byte(rawPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), []byte(rawPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Manager{
		issuer:           issuer,
		accessTokenLife:  accessTokenLife,
		refreshTokenLife: refreshTokenLife,
		publicKey:        publicKey,
		privateKey:       privateKey,
		repo:             repo,
	}, nil
}

// Login returns a new access-refresh token pair for the given claims.
//
// The "iss", "iat" and "exp" claims are set internally by this function.
func (m *Manager) Login(ctx context.Context, claims Claims) (TokenDetails, TokenDetails, error) {
	claims.Iss = m.issuer

	// Access token is a signed JWT.
	accessTokenDetails, err := m.createJwt(claims)
	if err != nil {
		return TokenDetails{}, TokenDetails{}, fmt.Errorf("failed to create access token: %w", err)
	}

	// Refresh token is opaque.
	refreshToken := uuid.NewString()
	refreshTokenHash := sha256Hex(refreshToken)

	// Expiry time of the refresh token.
	expiresAt := time.Now().Add(m.refreshTokenLife)

	if err := m.repo.Insert(ctx, claims.Sub, refreshTokenHash, expiresAt); err != nil {
		return TokenDetails{}, TokenDetails{}, fmt.Errorf("failed to insert refresh token: %w", err)
	}

	return accessTokenDetails, TokenDetails{Token: refreshToken, ExpiresAt: expiresAt.Unix()}, nil
}

// Refresh checks if the given refreshToken is valid (not revoked + not expired). If valid, a new access-refresh token
// pair is issued, otherwise all refresh tokens for the user are revoked.
func (m *Manager) Refresh(ctx context.Context, claims Claims, refreshToken string) (TokenDetails, TokenDetails, error) {
	newRefreshToken := uuid.NewString()
	oldRefreshTokenHash := sha256Hex(refreshToken)
	newRefreshTokenHash := sha256Hex(newRefreshToken)

	// Expiry time of the refresh token.
	expiresAt := time.Now().Add(m.refreshTokenLife)

	// This call will fail if the refresh token is revoked or expired.
	if err := m.repo.Refresh(ctx, oldRefreshTokenHash, newRefreshTokenHash, expiresAt); err != nil {
		return TokenDetails{}, TokenDetails{}, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	// Access token is a signed JWT.
	accessTokenDetails, err := m.createJwt(claims)
	if err != nil {
		return TokenDetails{}, TokenDetails{}, fmt.Errorf("failed to create access token: %w", err)
	}

	return accessTokenDetails, TokenDetails{Token: newRefreshToken, ExpiresAt: expiresAt.Unix()}, nil
}

// Logout revokes the given refresh token.
func (m *Manager) Logout(ctx context.Context, refreshToken string) error {
	refreshTokenHash := sha256Hex(refreshToken)

	if err := m.repo.Revoke(ctx, refreshTokenHash); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}

// DecodeSafe decodes the given access token after verifying its signature.
func (m *Manager) DecodeSafe(accessToken string) (Claims, error) {
	parsed, err := jwt.Parse([]byte(accessToken), jwt.WithKey(jwa.ES256(), m.publicKey))
	if err != nil {
		return Claims{}, fmt.Errorf("failed to parse access token: %w", err)
	}

	// Marshal claims for convenient unmarshalling.
	claimBytes, err := json.Marshal(parsed)
	if err != nil {
		return Claims{}, fmt.Errorf("failed to marshal claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return Claims{}, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

// createJwt creates a signed JWT with the given claims.
func (m *Manager) createJwt(claims Claims) (TokenDetails, error) {
	t := jwt.New()
	now := time.Now()

	claims.Iss = m.issuer
	claims.Iat = now.Unix()
	claims.Exp = now.Add(m.accessTokenLife).Unix()

	// Set all claims.
	errs := []error{
		t.Set(jwt.IssuerKey, claims.Iss),
		t.Set(jwt.ExpirationKey, claims.Exp),
		t.Set(jwt.IssuedAtKey, claims.Iat),
		t.Set(jwt.SubjectKey, claims.Sub),
		t.Set("email", claims.Email),
		t.Set("given_name", claims.GivenName),
		t.Set("family_name", claims.FamilyName),
		t.Set("picture", claims.Picture),
	}

	// If any Set operation failed, return error.
	for _, err := range errs {
		if err != nil {
			return TokenDetails{}, fmt.Errorf("error while setting claim value: %w", err)
		}
	}

	// Sign using the private key.
	signed, err := jwt.Sign(t, jwt.WithKey(jwa.ES256(), m.privateKey))
	if err != nil {
		return TokenDetails{}, fmt.Errorf("failed to sign jwt: %w", err)
	}

	return TokenDetails{Token: string(signed), ExpiresAt: claims.Exp}, nil
}

func sha256Hex(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
