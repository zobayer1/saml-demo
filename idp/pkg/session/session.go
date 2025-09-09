package session

import (
	"crypto/sha256"
	"net/http"

	"github.com/gorilla/sessions"
)

var Store *sessions.CookieStore

func InitSession(secret string) {
	hash := sha256.Sum256([]byte(secret))

	Store = sessions.NewCookieStore(hash[:])

	Store.Options = &sessions.Options{
		Path:     "/",
		Domain:   "idp.localhost",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
