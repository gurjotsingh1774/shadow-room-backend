package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const InfiltrationChallengeLifespan = 60 * time.Second

// Challenge stages a volatile timed verification challenge for an operative returning to the grid.
func (ih *InfiltrationHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Grid Error: Transport method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChallengeIssuanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Infiltration Error: Invalid input parameters", http.StatusBadRequest)
		return
	}

	// 1. Confirm identity registration tracking context exists before allocating resources
	if _, exists := ih.Registry.FetchOperative(req.OperativeID); !exists {
		http.Error(w, "Access Denied: Operative profile not registered on this node", http.StatusNotFound)
		return
	}

	// 2. Generate a high-entropy validation challenge string (Nonce)
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "Grid Error: Failed to gather high-entropy systemic noise", http.StatusInternalServerError)
		return
	}
	challengeNonce := hex.EncodeToString(nonceBytes)

	// 3. Securely stage the challenge parameters within the registry matrix
	ih.Registry.IssueHandshake(req.OperativeID, challengeNonce, InfiltrationChallengeLifespan)

	// 4. Dispatch the challenge payload across the wire back to the operative terminal
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"nonce":"%s"}`, challengeNonce)
}
