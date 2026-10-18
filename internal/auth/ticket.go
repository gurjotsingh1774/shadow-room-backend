package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"shadow-room-backend/internal/middleware" // Pointing to your updated middleware package
)

// IssueWSTicket serves as the secure conduit bridging an active, authenticated
// session cookie over to a volatile, short-lived WebSocket infiltration ticket.
//
// Because browsers cannot explicitly attach custom authorization headers or cookies
// cleanly to the native WebSocket initialization API, the client fetches this
// high-entropy ticket right before opening the socket connection. The ticket is
// opaque, carries zero inherited session footprints, and is consumed instantly at entry.
func (ih *InfiltrationHandler) IssueWSTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Grid Error: Transport method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Recover the operative's identity from the type-safe context key set by GuardInfiltration
	operativeID, _ := r.Context().Value(middleware.OperativeIDKey).(string)
	if operativeID == "" {
		http.Error(w, "Access Denied: Session validation state missing from execution context", http.StatusUnauthorized)
		return
	}

	// 2. Instruct the volatile vault cache to mint a single-use token tied to this identity
	ticketToken, err := ih.Vault.MintInfiltrationTicket(r.Context(), operativeID)
	if err != nil {
		log.Printf("shadowroom/telemetry: failed to stage infiltration ticket for operative %s: %v", operativeID, err)
		http.Error(w, "Grid Error: Internal cryptographic token issuance failure", http.StatusInternalServerError)
		return
	}

	// 3. Return the single-use token alongside its structural expiration constraint
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ticket":           ticketToken,
		"expiresInSeconds": 60, // Enforces explicit fast-consumption boundaries
	})
}
