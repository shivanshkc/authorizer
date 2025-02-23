# Authorizer

Authorizer is a secure OAuth service written in Go.

## Security Features

- CSRF protection using the "state" parameter. ([Read more](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12))
- Authorization code interception protection using PKCE with S256 challenge method. ([Read more](https://datatracker.ietf.org/doc/html/rfc7636))
- Access token exchange using HTTP only cookies.

## Deployment

