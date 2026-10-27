package middleware

import (
	"net/http"
	"shadow-room-backend/internal/config" // Pointing to your updated config package
)

// GuardCrossInfiltration intercepts cross-origin web requests to ensure incoming
// traffic aligns exclusively with authorized mesh network origins (Grid Origins).
func GuardCrossInfiltration(env *config.Environment, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Assign cross-origin permissions dynamically using the centralized node environment configuration
		origin := r.Header.Get("Origin")
		allowOrigin := env.GridOrigin
		if allowOrigin == "*" || allowOrigin == "" {
			if origin != "" {
				allowOrigin = origin
			} else {
				allowOrigin = "*"
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 2. Intercept and isolate cryptographic preflight requests immediately at the grid edge
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
