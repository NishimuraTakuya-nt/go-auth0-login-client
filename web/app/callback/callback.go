package callback

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"01-Login/platform/authenticator"
)

// Handler for our callback.
func Handler(auth *authenticator.Authenticator) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		if ctx.Query("state") != session.Get("state") {
			ctx.String(http.StatusBadRequest, "Invalid state parameter.")
			return
		}
		// FIXME //////////////////////////////////////////////////////////////////////
		// Call token exchange service
		tokenExchangeReq := struct {
			Code string `json:"code"`
		}{
			Code: ctx.Query("code"),
		}

		jsonData, err := json.Marshal(tokenExchangeReq)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to marshal token exchange request.")
			return
		}

		resp, err := http.Post(
			"http://localhost:8082/api/v1/auth/token-exchange",
			"application/json",
			bytes.NewBuffer(jsonData),
		)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to exchange token with authentication service.")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			ctx.String(resp.StatusCode, "Token exchange service returned an error.")
			return
		}

		// Parse response
		var tokenResponse struct {
			IDToken   string `json:"idToken"`
			ExpiresAt int64  `json:"expiresAt"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to decode token response.")
			return
		}
		// >FIXME //////////////////////////////////////////////////////////////////////

		// Exchange an authorization code for a token.
		// memo: ここで認証コードをトークンに交換してる
		//token, err := auth.Exchange(ctx.Request.Context(), ctx.Query("code")) // FIXME: もともとのコード
		//if err != nil {
		//	ctx.String(http.StatusUnauthorized, "Failed to convert an authorization code into a token.")
		//	return
		//}
		//
		//idToken, err := auth.VerifyIDToken(ctx.Request.Context(), token)
		//if err != nil {
		//	ctx.String(http.StatusInternalServerError, "Failed to verify ID Token.")
		//	return
		//}
		//
		//var profile map[string]interface{}
		//if err := idToken.Claims(&profile); err != nil {
		//	ctx.String(http.StatusInternalServerError, err.Error())
		//	return
		//}

		//session.Set("access_token", token.AccessToken)
		//session.Set("profile", profile) // FIXME: もともとのコード
		//if err := session.Save(); err != nil {
		//	ctx.String(http.StatusInternalServerError, err.Error())
		//	return
		//}

		// Redirect to logged in page.
		ctx.Redirect(http.StatusTemporaryRedirect, "/user")
	}
}
