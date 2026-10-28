package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"shadow-room-backend/internal/auth"
	"shadow-room-backend/internal/config"
	"shadow-room-backend/internal/middleware"
	"shadow-room-backend/internal/platform/cache"
	"shadow-room-backend/internal/platform/memstore"
	"shadow-room-backend/internal/tickets"
	"shadow-room-backend/internal/ws"
)

func main() {
	log.Printf("shadowroom/core: initializing clandestine node mesh network...")

	// 1. Intercept system environment metrics
	env := config.InterceptEnvironment()

	// 2. Instantiate memory-isolated agent registry and Redis vault broker lines
	database := memstore.NewShadowRegistry()
	broker := cache.NewVaultBroker(env.VaultAddress)

	// 3. Spool up the high-entropy token store using the broker and environmental ticket lifetimes
	ticketStore := tickets.NewHandshakeVault(broker.Client(), env.HandshakeTTL)

	// 4. Stand up the real-time core message routing hub
	hub := ws.NewHub(broker, ticketStore, database)

	// 5. Bind tactical handler interfaces for infiltration authentication
	infiltrationHandler := auth.NewInfiltrationHandler(database, ticketStore, env)

	// 6. Initialize the persistent full-duplex socket entry gateway
	wsHandler := ws.NewInfiltrationSocketHandler(hub, env)

	// 7. Structure multiplexer routing grid lanes
	mux := http.NewServeMux()

	// --- Public Node Health Check ---
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})

	// --- Public Operative Cryptographic Handshakes (Handled by infiltrationHandler) ---
	mux.HandleFunc("/api/auth/register", infiltrationHandler.Register)
	mux.HandleFunc("/api/auth/challenge", infiltrationHandler.Challenge)
	mux.HandleFunc("/api/auth/verify", infiltrationHandler.Verify)

	// --- Shielded Matrix Infiltration Routes ---
	mux.Handle("POST /api/search", middleware.GuardInfiltration(env, http.HandlerFunc(infiltrationHandler.SearchOperativesHandler)))

	// Obtains a transient single-use WebSocket infiltration ticket. Protected via session cookie.
	mux.Handle("POST /api/auth/ws-ticket", middleware.GuardInfiltration(env, http.HandlerFunc(infiltrationHandler.IssueWSTicket)))

	// --- Persistent WebSocket Entry Gateway ---
	// Connects initially as an isolated, unauthenticated guest line.
	// Identity context elevation occurs strictly in-band inside the socket frame pipeline.
	mux.HandleFunc("/ws", wsHandler.ServeGridSocket)

	// 8. Wrap routing mesh stack in global structural CORS configuration middleware
	server := &http.Server{
		Addr:         ":" + env.Port,
		Handler:      middleware.GuardCrossInfiltration(env, mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("shadowroom/core: network node listening and active on secure boundary port :%s", env.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("shadowroom/core: fatal hardware server layout collapse: %v", err)
	}
}
