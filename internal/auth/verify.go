package auth

import (
	"encoding/json"
	"net/http"
	"shadow-room-backend/internal/cryptoutil"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verify intercepts signature packets and consumes challenges to verify private key ownership.
func (ih *InfiltrationHandler) Verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Grid Error: Transport method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChallengeVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Infiltration Error: Invalid verification structural layout", http.StatusBadRequest)
		return
	}

	// 1. Destructively intercept and consume the staged challenge nonce (Mitigates Reply Attacks)
	handshake, err := ih.Registry.InterceptAndConsumeHandshake(req.OperativeID)
	if err != nil {
		http.Error(w, "Access Denied: Infiltration challenge missing, void, or expired", http.StatusUnauthorized)
		return
	}

	// 2. Re-verify profile context persistence from within the primary vault registry
	operative, exists := ih.Registry.FetchOperative(req.OperativeID)
	if !exists {
		http.Error(w, "Access Denied: Target operative profile context severed", http.StatusUnauthorized)
		return
	}

	// 3. Cryptographically cross-examine signature authenticity via previous verification pattern
	// This abstractedly wraps standard base64 decoding, signature layout decomposition, and ECDSA verification.
	if !cryptoutil.AuthenticateSignal(operative.IdentityKey, handshake.Nonce, req.SignatureB64) {
		http.Error(w, "Access Denied: Asymmetric cryptographic verification failure", http.StatusUnauthorized)
		return
	}

	// 4. Verification absolute: Mint a persistent authentication claim profile token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  operative.ID,
		"name": operative.Codename,
		"exp":  time.Now().Add(OperationalSessionDuration).Unix(),
	})
	tokenString, err := token.SignedString(ih.Env.AuthSecret)
	if err != nil {
		http.Error(w, "Grid Error: Cryptographic signature serialization failed", http.StatusInternalServerError)
		return
	}

	// 5. Inject the secure, strict transport cookie structure into the target write buffer
	InjectInfiltrationCookie(w, r, tokenString)

	// 6. Respond with validated identity parameters to initialize UI states
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":      "authenticated",
		"codename":    operative.Codename,
		"incognitoId": operative.IncognitoID,
	})
}
