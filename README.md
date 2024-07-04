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

**Endpoint:** `GET /api/auth/{provider}`

**Parameters:**
- **Path Parameter:**
    - `provider`: Specifies the OAuth provider. The only supported provider currently is `google`.
- **Query Parameter:**
    - `redirect_uri`: The URL where the user will be redirected after authentication. Ensure this URL is in the allowed list in the application config before use.

**Authentication Result**

- **Success:** The final URL will contain an `id_token` query parameter, which is a JWT that can be decoded to retrieve user details.
- **Failure:** The final URL will contain an `error` query parameter with the failure reason.

### Get User Details

**Endpoint:** `GET /api/user`

**Parameters:**
- **Headers:**
    - `Authorization`: The access token obtained using the auth API.

**Success Response**
```json5
{
    "_id": "6683b25382af3a39b661ee2f", // Hex code
    "email": "example@gmail.com", // Email used during OAuth
    "first_name": "John", 
    "last_name": "Doe",
    "picture_link": "https://photos.com/abc", // Picture link as obtained from Google.
    "created_at": "2024-07-02T07:54:59.125Z",
    "updated_at": "2024-07-04T18:58:01.891Z"
}
```

**Error Responses**
 - 401 if the access token is absent or malformed.
 - 404 if the user does not exist.
 - 500 if an unexpected error occurs.

**Note**: The `/api/user` route can also be invoked using the `HEAD` verb which will not return the user's details, but
it can be used to check the validity of the token. Also, it works much faster than the `GET` one.
