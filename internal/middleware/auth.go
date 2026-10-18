package middleware

import (
	"context"
	"net/http"

	"shadow-room-backend/internal/config" // Pointing to your updated config package

	"github.com/golang-jwt/jwt/v5"
)

// contextKey defines a distinct type for injection to prevent runtime key collisions.
type contextKey string

// OperativeIDKey is the explicit, type-safe gatekeeper used to extract or inject
// authenticated user identities across HTTP execution contexts.
const OperativeIDKey contextKey = "shadowroom.operative_id"

// GuardInfiltration validates incoming transport session cookies using the node's
// centralized cryptographic secret. If valid, the operative's ID is injected down-stack.
func GuardInfiltration(env *config.Environment, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Locate the persistent auth cookie within the incoming grid request
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Access Denied: Operative session missing from grid", http.StatusUnauthorized)
			return
		}

		// 2. Parse and verify the authenticity of the token using the system configuration secret
		token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
			// Ensure token signing method is symmetric HMAC as expected
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return env.AuthSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Access Denied: Authentication signature void or compromised", http.StatusUnauthorized)
			return
		}

		// 3. Extract the underlying subject claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Grid Error: Failed to evaluate identity claims mapping", http.StatusInternalServerError)
			return
		}

		operativeID, ok := claims["sub"].(string)
		if !ok || operativeID == "" {
			http.Error(w, "Access Denied: Identity token missing subject declaration", http.StatusUnauthorized)
			return
		}

		// 4. Inject the validated identity down-stack using type-safe keys
		ctx := context.WithValue(r.Context(), OperativeIDKey, operativeID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
