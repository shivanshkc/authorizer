# Authorizer

Authorizer is a secure OAuth service written in Go. Currently, Authorizer supports only Google OAuth, but
it can be extended to any provider by implementing the `oauth.Provider` interface present in the `pkg/oauth` package.
Contributions are welcome.

## Security Features

- CSRF protection using the "state" parameter. ([Read more](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12))
- Authorization code interception protection using PKCE with S256 challenge method. ([Read more](https://datatracker.ietf.org/doc/html/rfc7636))
- Access token exchange using HTTP only cookies.

## Google Client ID and Secret

Google Client ID and Client Secret are mandatory configs to make Google OAuth work.
If you don't already have them, find instructions [here](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid).

## Quickstart

1. Make sure you have Docker (or Podman) installed and a PostgreSQL running.
2. Create a config file by executing:
    ```
    cp configs/configs.sample.yaml configs/configs.yaml
    ```
3. Update the `configs.yaml` file with your database details, Google Client ID, Secret etc.
4. Build the image.
    ```
    make image
    ```
5. Run container.
    ```
    make container
    ```
6. Go to `http://localhost:8080/api/google?redirect_url=http://localhost:8080` to start Sign in with Google.
7. After signing in, you will be redirected to the specified `redirect_url` with an HTTP only cookie that contains the 
access token.
8. Now, if you open the network tab and go to `http://localhost:8080/api/check`, the response headers will contain the
following headers, `X-Auth-Email`, `X-Auth-Name`, `X-Auth-Picture`.
