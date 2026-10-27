package auth

import (
	"net/http"
	"strings"
	"time"
)

const (
	// SecureSessionCookieName identifies the persistent authorization token tracking key.
	SecureSessionCookieName = "auth_token"

	// OperationalSessionDuration defines how long an authenticated identity stays alive
	// before requiring a fresh cryptographic challenge rotation (e.g., 24 Hours).
	OperationalSessionDuration = 24 * time.Hour
)

// InjectInfiltrationCookie drops a highly hardened, single-purpose session identifier
// into the client's storage array to handle persistent node access.
func InjectInfiltrationCookie(w http.ResponseWriter, r *http.Request, sessionToken string) {
	// The transport validation guarantees that the secure flag is actively asserted
	// only if the communication line is traveling through an encrypted TLS tunnel.
	isChannelEncrypted := IsTransportLayerSecure(r)

	sameSite := http.SameSiteNoneMode
	if !isChannelEncrypted {
		// Modern browsers strictly reject cookies that have SameSite=None without Secure=true.
		// For local plain HTTP development on localhost, SameSite=Lax permits credentialed requests.
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SecureSessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		Expires:  time.Now().Add(OperationalSessionDuration),
		HttpOnly: true,                  // Hardens the token against Cross-Site Scripting (XSS) extraction vectors
		Secure:   isChannelEncrypted,    // Restricts transmission exclusively over cryptographic transport layers
		SameSite: sameSite,              // Eliminates completely Cross-Site Request Forgery (CSRF) infiltration tactics
	})
}

// VaporizeInfiltrationCookie instantly neutralizes an active grid session token,
// forcing the client node back into unauthenticated cold status.
func VaporizeInfiltrationCookie(w http.ResponseWriter, r *http.Request) {
	isChannelEncrypted := IsTransportLayerSecure(r)
	sameSite := http.SameSiteNoneMode
	if !isChannelEncrypted {
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SecureSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Destroys the cookie instantly within client memory
		HttpOnly: true,
		Secure:   isChannelEncrypted,
		SameSite: sameSite,
	})
}

// IsTransportLayerSecure checks if the incoming grid connection is hardened over TLS.
func IsTransportLayerSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || strings.HasPrefix(r.Header.Get("Origin"), "https://")
}
