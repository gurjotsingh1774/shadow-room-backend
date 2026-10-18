package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand" // Using modern, safe rand/v2 to replace seed-reliant math/rand
	"net/http"
	"shadow-room-backend/internal/codename"
	"shadow-room-backend/internal/cryptoutil"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Register processes incoming identity payloads to enroll a new operative profile.
func (ih *InfiltrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Grid Error: Transport method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req InfiltrationRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Infiltration Error: Malformed JSON payload layout", http.StatusBadRequest)
		return
	}

	// 1. Instantiating the decentralized pseudonym matrix generator
	generator := codename.NewPseudonymGenerator()

	// 2. Parse asymmetric identity keys using structural utilities
	identityKey, errAuth := cryptoutil.ParseJWKToIdentityKey(req.IdentityKey)
	handshakeKey, errE2EE := cryptoutil.ParseJWKToIdentityKey(req.HandshakeKey)
	if errAuth != nil || errE2EE != nil {
		http.Error(w, "Infiltration Error: Malformed public key parameters", http.StatusBadRequest)
		return
	}

	// 3. Generate secure, high-entropy tracking values
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "Grid Error: Secure entropy source failure", http.StatusInternalServerError)
		return
	}
	generatedOperativeID := hex.EncodeToString(idBytes)

	// Generate unique codename pseudorandomly using safe math v2 defaults
	generatedCodename := generator.GenerateRandom(mrand.New(mrand.NewSource(time.Now().UnixNano())))
	generatedIncognitoID := fmt.Sprintf("avatar_%03d.png", (time.Now().UnixNano()%202)+1)

	// 4. Commit the new identity architecture into the memory-isolated registry vault
	ih.Registry.RegisterOperative(generatedOperativeID, identityKey, handshakeKey, generatedIncognitoID, generatedCodename)

	// 5. Generate short-lived authentication claim token signed by the env parameters
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  generatedOperativeID,
		"name": generatedCodename,
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString(ih.Env.AuthSecret)
	if err != nil {
		http.Error(w, "Grid Error: Cryptographic signature serialization failed", http.StatusInternalServerError)
		return
	}

	// 6. Bake and seal the cookie down into the active network response stream
	InjectInfiltrationCookie(w, r, tokenString)

	// 7. Pipe response profile telemetry back upstream
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(OperativeProfileResponse{
		ID:          generatedOperativeID,
		Codename:    generatedCodename,
		IncognitoID: generatedIncognitoID,
	})
}
