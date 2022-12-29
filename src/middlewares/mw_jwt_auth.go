package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/shivanshkc/authorizer/src/logger"
	"github.com/shivanshkc/authorizer/src/oauth"
	"github.com/shivanshkc/authorizer/src/utils/errutils"
	"github.com/shivanshkc/authorizer/src/utils/httputils"
)

// JWTAuth authenticates incoming requests.
func JWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// Obtain the access token from the request.
		accessToken := request.Header.Get("Authorization")
		if accessToken == "" {
			reason := "access token not present in request"
			logger.Info(request.Context(), reason)
			httputils.WriteErr(writer, errutils.Unauthorized().WithReasonStr(reason))
			return
		}

		// Check if auth type is bearer.
		if !strings.HasPrefix(accessToken, "Bearer ") {
			reason := "only bearer auth is required"
			logger.Info(request.Context(), reason)
			httputils.WriteErr(writer, errutils.Unauthorized().WithReasonStr(reason))
			return
		}

		// TODO: At the time of writing this, the only provider in use was Google.
		// So, we're using the GoogleClaims here. If any new providers are introduced, this will have to be updated.
		googleClaims := &oauth.GoogleClaims{}

		// Verify the JWT.
		// TODO: This auth means almost nothing. There's no signature or even claim verification!
		if err := oauth.JWTDecodeUnsafe(accessToken[7:], googleClaims); err != nil {
			reason := fmt.Sprintf("invalid token: %+v", err)
			logger.Info(request.Context(), reason)
			httputils.WriteErr(writer, errutils.Unauthorized().WithReasonStr(reason))
			return
		}

		// Serving standard requests further.
		next.ServeHTTP(writer, request)
	})
}
