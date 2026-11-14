# Token Manager Migration Handover Guide

This document explains the architecture, current state, and remaining steps for migrating Authorizer from third-party OAuth provider tokens (e.g. Google ID tokens) to **Authorizer's own ECDSA-signed JWT access tokens and opaque refresh tokens**.

---

## 1. Context & Motivation

Previously, Authorizer forwarded the upstream OAuth provider's ID token directly to clients via a single session cookie (`session`).

### New Architecture
- **Access Token**: Short-lived (e.g. 10m) ECDSA-signed JWT issued by Authorizer.
  - Cookie name: `access_token`
  - Cookie path: `/`
  - Used by reverse proxies / downstream services via `/api/check`.
- **Refresh Token**: Long-lived (e.g. 30d) opaque random string (UUID) stored hashed (`SHA-256`) in PostgreSQL.
  - Cookie name: `refresh_token`
  - Cookie path: `/api/refresh`
  - Used exclusively to rotate and obtain a fresh access-refresh token pair.

---

## 2. Current Implementation State

The branch compiles cleanly and all unit tests pass (`go test -count=1 ./...`).

### Completed
1. **`pkg/tokener` (Token Engine)**:
   - `types.go`: Added `TokenDetails` (`Token`, `ExpiresAt`).
   - `manager.go`:
     - Initialized with `issuer`, `accessTokenLife`, `refreshTokenLife`, and ECDSA keys.
     - `Login(...)`: Generates signed JWT access token and hashes/stores refresh token in repository.
     - `Refresh(...)`: Rotates refresh token in repository and generates a new access token.
     - `Logout(...)`: Revokes refresh token in repository.
     - `createJwt(...)`: Signs JWT using ES256 and sets `iss`, `iat`, `exp` claims.
2. **Configuration (`configs/configs.sample.yaml`, `internal/config/config.go`)**:
   - Added `auth` configuration block with `access_token_age_sec`, `refresh_token_age_sec`, `public_key`, and `private_key`.
3. **Issuer Extraction (`internal/utils/httputils/utils.go`)**:
   - Added `DomainFromURL(raw string)` to parse hostnames (without ports) for JWT `iss`.
4. **OAuth Callback Handler (`internal/handler/handler_callback.go`)**:
   - Calls `tokenManager.Login(ctx, claims)` on successful OAuth code exchange.
   - Sets dual HTTP-only strict cookies:
     - `access_token` on `/`
     - `refresh_token` on `/api/refresh`
5. **Dependency Wiring (`cmd/authorizer/main.go`, `internal/handler/handler.go`)**:
   - `tokener.NewManager(...)` instantiated and injected into `handler.NewHandler(...)`.
6. **Repository Interface & Stubs (`internal/repository/`)**:
   - `repository.Repository` embeds `tokener.Repository`.
   - Stubs implemented in `internal/repository/auth.go` returning `ErrNotImplemented` so the project compiles.
7. **Unit Test Updates (`internal/handler/`)**:
   - `handler_callback_test.go` updated to inject `tokenManager` and assert both `access_token` and `refresh_token` cookies.
   - `handler_auth_test.go` and `mock_repository_test.go` updated with stubs for `tokener.Repository`.

---

## 3. Next Steps Checklist (When Resuming)

### Step 1: Database Migration for Refresh Tokens
Create a new migration file: `db/migrations/000002_create_refresh_tokens_table.up.sql` and matching `.down.sql`:

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_sub VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_sub ON refresh_tokens(user_sub);
```

### Step 2: Implement Repository Methods (`internal/repository/auth.go`)
Replace the stubs with real PostgreSQL queries:
- **`Insert(ctx, sub, tokenHash, expiresAt)`**:
  - `INSERT INTO refresh_tokens (user_sub, token_hash, expires_at) VALUES ($1, $2, $3)`
- **`Refresh(ctx, oldTokenHash, newTokenHash, expiresAt)`**:
  - In a database transaction:
    - Verify `oldTokenHash` is not revoked and `expires_at > NOW()`.
    - Mark `oldTokenHash` as revoked (`revoked = TRUE`).
    - Insert `newTokenHash` with the new expiration.
    - If `oldTokenHash` was already revoked, revoke all tokens for that `user_sub` (reuse detection).
- **`Revoke(ctx, tokenHash)`**:
  - `UPDATE refresh_tokens SET revoked = TRUE, updated_at = NOW() WHERE token_hash = $1`
- **`RevokeAll(ctx, sub)`**:
  - `UPDATE refresh_tokens SET revoked = TRUE, updated_at = NOW() WHERE user_sub = $1`

### Step 3: Update Session Check Endpoint (`internal/handler/handler_check.go`)
Currently `/api/check` looks up the issuer from the cookie and attempts to verify it using Google/Discord providers (`provider.DecodeToken`).

**Required changes**:
1. Read the `access_token` cookie.
2. Verify and decode using `h.tokenManager.DecodeSafe(cookie.Value)` (or verify with ECDSA public key).
3. Populate identity headers (`X-Auth-Email`, `X-Auth-Name`, `X-Auth-Picture`) from `tokener.Claims`.

### Step 4: Implement `/api/refresh` Endpoint
1. Create `internal/handler/handler_refresh.go`:
   - Handler reads the `refresh_token` cookie.
   - Decodes claims from access token or user sub.
   - Calls `h.tokenManager.Refresh(ctx, claims, refreshToken)`.
   - Issues new `access_token` and `refresh_token` cookies.
2. Register route in `internal/http/server.go`:
   ```go
   router.HandleFunc("/api/refresh", s.Handler.Refresh).Methods(http.MethodPost)
   ```

### Step 5: (Optional) Implement `/api/logout` Endpoint
1. Handler reads `refresh_token` cookie.
2. Calls `h.tokenManager.Logout(ctx, refreshToken)`.
3. Clears both `access_token` and `refresh_token` cookies by setting `MaxAge: -1`.
4. Register route in `internal/http/server.go`.

### Step 6: Public/Private Key Format Handling (`pkg/tokener/manager.go`)
`ecdsa.ParseRawPrivateKey` and `ParseUncompressedPublicKey` expect raw curve bytes.
If keys are stored in YAML as hex or PEM strings, add proper decoding:
```go
// e.g. for hex keys:
rawPrivBytes, err := hex.DecodeString(rawPrivateKey)
```

### Step 7: Update Unit & Integration Tests
1. `internal/handler/handler_callback_test.go`:
   - Inject a mock or test instance of `tokenManager`.
   - Assert both `access_token` and `refresh_token` cookies are set.
2. `internal/handler/handler_check_test.go`:
   - Test `/api/check` with tokens signed by `tokenManager`.
3. Add tests for `handler_refresh.go` and `internal/repository/auth.go`.
