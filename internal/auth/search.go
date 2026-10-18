package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"shadow-room-backend/internal/cryptoutil"
	"shadow-room-backend/internal/platform/memstore"
)

// SearchOperativesRequest represents the payload for searching registered
// operatives by codename or operative ID.
type SearchOperativesRequest struct {
	Query string `json:"query"`
}

// SearchOperativesHandler sweeps the active network registry to locate
// registered anonymous identities whose codename OR operative ID matches the
// supplied query.
//
// This must match on ID as well as codename: the frontend's group E2EE flow
// (MessageSystem.establishGroupSenderKey, the incoming-message handler in
// chat-container.tsx, etc.) looks up a room member's public keys by POSTing
// their raw operative ID here whenever that member isn't already a cached
// contact -- which is the normal case for any peer you've only ever seen
// inside a group room and never messaged 1-to-1. Searching codenames alone
// means that lookup always comes back empty for such peers, so their public
// keys never resolve, sender-key distribution silently gets skipped, and
// clients are left permanently missing each other's group sender keys.
func (ih *InfiltrationHandler) SearchOperativesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Grid Error: Transport method not allowed", http.StatusMethodNotAllowed)
		return
	}


	var req SearchOperativesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Infiltration Error: Malformed directory request layout", http.StatusBadRequest)
		return
	}

	// Normalize and validate the search query.
	searchQuery := strings.TrimSpace(req.Query)
	if len(searchQuery) < 2 {
		http.Error(w, "Infiltration Error: Search sequence too short for stable interception", http.StatusBadRequest)
		return
	}

	// Query the registry for matching codenames, operative IDs, and public rooms.
	matchedByID := ih.Registry.InterceptIdentities(searchQuery)
	matchedByCodename := ih.Registry.InterceptCodenames(searchQuery)
	matchedRooms := ih.Registry.InterceptPublicRooms(searchQuery)

	// Merge the ID and codename matches, de-duplicating by operative ID
	// (a full-ID query will hit InterceptIdentities; a codename query hits
	// InterceptCodenames; either should surface the same profile once).
	seen := make(map[string]bool, len(matchedByID)+len(matchedByCodename))
	matchedOperatives := make([]*memstore.Operative, 0, len(matchedByID)+len(matchedByCodename))
	for _, op := range matchedByID {
		if !seen[op.ID] {
			seen[op.ID] = true
			matchedOperatives = append(matchedOperatives, op)
		}
	}
	for _, op := range matchedByCodename {
		if !seen[op.ID] {
			seen[op.ID] = true
			matchedOperatives = append(matchedOperatives, op)
		}
	}

	// Prepare the sanitized response.
	directoryResponse := make([]OperativeProfileResponse, 0, len(matchedOperatives)+len(matchedRooms))

	// 1. Add matching public rooms first
	for _, r := range matchedRooms {
		directoryResponse = append(directoryResponse, OperativeProfileResponse{
			ID:          r.ID,
			Codename:    r.ID,
			IncognitoID: "room_avatar_001.png", // Generic room avatar asset identifier
			IsRoom:      true,
		})
	}

	// 2. Add matching operatives
	for _, op := range matchedOperatives {

		idJWK := cryptoutil.ConvertPublicKeyToJWK(op.IdentityKey)
		hsJWK := cryptoutil.ConvertPublicKeyToJWK(op.HandshakeKey)

		directoryResponse = append(directoryResponse, OperativeProfileResponse{
			ID:           op.ID,
			Codename:     op.Codename,
			IncognitoID:  op.IncognitoID,
			IdentityKey:  cryptoutil.ExtractPublicKeyToPEM(op.IdentityKey),
			HandshakeKey: cryptoutil.ExtractPublicKeyToPEM(op.HandshakeKey),
			IdentityJWK:  &idJWK,
			HandshakeJWK: &hsJWK,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(directoryResponse); err != nil {
		http.Error(w, "Grid Error: Failed to encode response", http.StatusInternalServerError)
		return
	}
}
