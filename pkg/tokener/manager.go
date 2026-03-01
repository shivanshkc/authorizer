package tokener

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Manager encapsulates methods required to create and manage access-refresh token pairs.
type Manager struct {
	refreshTokenExpiry time.Duration

	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey

	repo Repository
}

// NewManager returns a new instance of the manager.
func NewManager(
	refreshTokenExpiry time.Duration, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, repo Repository,
) *Manager {
	return &Manager{
		refreshTokenExpiry: refreshTokenExpiry,
		publicKey:          publicKey,
		privateKey:         privateKey,
		repo:               repo,
	}
}

// Login returns a new access-refresh token pair for the given claims.
func (m *Manager) Login(ctx context.Context, claims Claims) (string, string, error) {
	// Access token is a signed JWT.
	accessToken, err := createJwt(claims, m.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create access token: %w", err)
	}

	// Refresh token is opaque.
	refreshToken := uuid.NewString()
	refreshTokenHash := sha256Hex(refreshToken)

	// Expiry time of the refresh token.
	expiresAt := time.Now().Add(m.refreshTokenExpiry)

	if err := m.repo.Insert(ctx, claims.Sub, refreshTokenHash, expiresAt); err != nil {
		return "", "", fmt.Errorf("failed to insert refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// Refresh checks if the given refreshToken is valid (not revoked + not expired). If valid, a new access-refresh token
// pair is issued, otherwise all refresh tokens for the user are revoked.
func (m *Manager) Refresh(ctx context.Context, claims Claims, refreshToken string) (string, string, error) {
	newRefreshToken := uuid.NewString()
	oldRefreshTokenHash := sha256Hex(refreshToken)
	newRefreshTokenHash := sha256Hex(newRefreshToken)

	// Expiry time of the refresh token.
	expiresAt := time.Now().Add(m.refreshTokenExpiry)

	// This call will fail if the refresh token is revoked or expired.
	if err := m.repo.Refresh(ctx, oldRefreshTokenHash, newRefreshTokenHash, expiresAt); err != nil {
		return "", "", fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	// Access token is a signed JWT.
	accessToken, err := createJwt(claims, m.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create access token: %w", err)
	}

	return accessToken, newRefreshToken, nil
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

	var claims Claims

	if err := parsed.Get("iss", &claims.Iss); err != nil {
		return Claims{}, fmt.Errorf("failed to decode iss claim: %w", err)
	}
	if err := parsed.Get("exp", &claims.Exp); err != nil {
		return Claims{}, fmt.Errorf("failed to decode exp claim: %w", err)
	}
	if err := parsed.Get("iat", &claims.Iat); err != nil {
		return Claims{}, fmt.Errorf("failed to decode iat claim: %w", err)
	}
	if err := parsed.Get("sub", &claims.Sub); err != nil {
		return Claims{}, fmt.Errorf("failed to decode sub claim: %w", err)
	}
	if err := parsed.Get("email", &claims.Email); err != nil {
		return Claims{}, fmt.Errorf("failed to decode email claim: %w", err)
	}
	if err := parsed.Get("given_name", &claims.GivenName); err != nil {
		return Claims{}, fmt.Errorf("failed to decode given_name claim: %w", err)
	}
	if err := parsed.Get("family_name", &claims.FamilyName); err != nil {
		return Claims{}, fmt.Errorf("failed to decode family_name claim: %w", err)
	}
	if err := parsed.Get("picture", &claims.Picture); err != nil {
		return Claims{}, fmt.Errorf("failed to decode picture claim: %w", err)
	}

	return claims, nil
}

// createJwt creates a JWT with the given claims, and signs it using the given private key.
func createJwt(claims Claims, privateKey *ecdsa.PrivateKey) (string, error) {
	t := jwt.New()

	// The caller is not allowed to set their own iat.
	claims.Iat = time.Now()

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
			return "", fmt.Errorf("error while setting claim value: %w", err)
		}
	}

	// Sign using the private key.
	signed, err := jwt.Sign(t, jwt.WithKey(jwa.ES256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %w", err)
	}

	return string(signed), nil
}

func sha256Hex(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
