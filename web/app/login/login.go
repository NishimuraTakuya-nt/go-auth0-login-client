package login

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/NishimuraTakuya-nt/go-auth0-login-client/platform/authenticator"
)

// Handler for our login.
func Handler(auth *authenticator.Authenticator) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		state, err := generateRandomState()
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		// Generate PKCE code_verifier
		codeVerifier, err := generateCodeVerifier()
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		// Generate code_challenge
		codeChallenge := generateCodeChallenge(codeVerifier)

		// Save state and code_verifier in session
		session := sessions.Default(ctx)
		session.Set("state", state)
		session.Set("code_verifier", codeVerifier)
		if err := session.Save(); err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		audience := os.Getenv("AUTH0_AUDIENCE")
		ctx.Redirect(
			http.StatusTemporaryRedirect,
			auth.AuthCodeURL(
				state,
				oauth2.SetAuthURLParam("audience", audience),
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			),
		)
	}
}

func generateCodeVerifier() (string, error) {
	// 43-128文字のランダムな文字列を生成
	b := make([]byte, 96) // 96バイトで128文字のbase64文字列になります
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	// SHA256でハッシュ化
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}
