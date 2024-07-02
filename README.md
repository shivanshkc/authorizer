# Authorizer

## Introduction

Authorizer is a dead simple authentication and authorization service based on OAuth.

## Deployment

To run an Authorizer instance, follow these steps:

1. **Clone the Repository:**
   ```sh
   git clone git@github.com:shivanshkc/authorizer.git
   cd authorizer
   ```

2. **Build the Container Image:**
   ```sh
   make image
   ```

3. **Run the Container:**
   ```sh
   docker run \
     --detach \
     --name authorizer \
     --net host \
     --volume <config file local path>:/etc/authorizer/configs.yaml \
     authorizer:latest
   ```

4. **Configuration:**
   - Authorizer accepts configuration in YAML format.
   - Refer to `configs/configs.sample.yaml` for the configuration schema.

## API Documentation

### Start Authentication Flow

**Endpoint:** `/api/auth/{provider}`

**Parameters:**
- **Path Parameter:**
    - `provider`: Specifies the OAuth provider. The only supported provider currently is `google`.
- **Query Parameter:**
    - `redirect_uri`: The URL where the user will be redirected after authentication. Ensure this URL is in the allowed list in the application config before use.

### Authentication Result

- **Success:** The final URL will contain an `id_token` query parameter, which is a JWT that can be decoded to retrieve user details.
- **Failure:** The final URL will contain an `error` query parameter with the failure reason.

## Future Plans

- Add an API to validate the `id_token` using the provider's official keys to verify the JWT signature.