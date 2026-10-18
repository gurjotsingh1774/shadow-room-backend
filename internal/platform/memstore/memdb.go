package memstore

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	// ErrAgentNotFound is returned when an operation references a non-existent agent.
	ErrAgentNotFound = errors.New("shadowroom/db: operative identity not found in registry")
	// ErrHandshakeMissing is returned when an auth challenge does not exist or has expired.
	ErrHandshakeMissing = errors.New("shadowroom/db: authentication challenge missing or expired")
)

// Operative represents an anonymous user identity within the Shadow Room network.
// It securely decouples real-world identities from network personas by relying entirely
// on cryptographic keypairs for authentication and End-to-End Encryption (E2EE).
type Operative struct {
	ID           string           // Unique cryptographic identifier or alias
	IdentityKey  *ecdsa.PublicKey // Long-term ECDSA key used exclusively for signing and authentication
	HandshakeKey *ecdsa.PublicKey // Ephemeral/Static ECDH key used for establishing E2EE shared secrets
	IncognitoID  string           // Visual/avatar identifier to maintain complete anonymity
	Codename     string           // User-defined pseudonym within the mesh network
}

// CryptographicHandshake represents a timed-challenge mechanism used to prove identity ownership.
type CryptographicHandshake struct {
	Nonce     string    // Random challenge string issued to the client
	ExpiresAt time.Time // Exact time boundary after which the challenge becomes void
}

// Room represents a secure group chat session within the Shadow Room network.
//
// Members is mutated (JoinRoom/LeaveRoom) and range-iterated (broadcast fan-out in the
// ws Hub) from independent goroutines. The registry's top-level roomsMu only protects the
// `rooms` map itself, not the contents of a *Room once a pointer has been handed out, so
// Room owns its own lock to guard concurrent access to Members. Always go through the
// Snapshot/Count/Has/AddMember/RemoveMember helpers below instead of touching Members
// directly to avoid "concurrent map read and map write" panics.
type Room struct {
	ID         string `json:"id"`
	Passphrase string `json:"passphrase"`
	Visibility string `json:"visibility"` // "public" | "private"
	CreatorID  string `json:"creatorId"`

	membersMu sync.RWMutex
	Members   map[string]bool `json:"members"` // Set of operative IDs
}

// Snapshot returns a point-in-time copy of the member ID set, safe to range over
// without holding any lock.
func (r *Room) Snapshot() []string {
	r.membersMu.RLock()
	defer r.membersMu.RUnlock()

	ids := make([]string, 0, len(r.Members))
	for id := range r.Members {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the current number of members.
func (r *Room) Count() int {
	r.membersMu.RLock()
	defer r.membersMu.RUnlock()
	return len(r.Members)
}

// Has reports whether the given operative is currently a member.
func (r *Room) Has(operativeID string) bool {
	r.membersMu.RLock()
	defer r.membersMu.RUnlock()
	return r.Members[operativeID]
}

// AddMember inserts an operative into the member set.
func (r *Room) AddMember(operativeID string) {
	r.membersMu.Lock()
	defer r.membersMu.Unlock()
	r.Members[operativeID] = true
}

// RemoveMember deletes an operative from the member set.
func (r *Room) RemoveMember(operativeID string) {
	r.membersMu.Lock()
	defer r.membersMu.Unlock()
	delete(r.Members, operativeID)
}

// ShadowRegistry serves as an in-memory, thread-safe vault managing the lifecycle of active
// operatives, secure rooms, and their volatile cryptographic handshakes.
type ShadowRegistry struct {
	operativesMu sync.RWMutex
	operatives   map[string]*Operative

	handshakesMu sync.RWMutex
	handshakes   map[string]CryptographicHandshake

	roomsMu sync.RWMutex
	rooms   map[string]*Room
}

// NewShadowRegistry instantiates an empty cryptographic vault for managing anonymous sessions.
func NewShadowRegistry() *ShadowRegistry {
	return &ShadowRegistry{
		operatives: make(map[string]*Operative),
		handshakes: make(map[string]CryptographicHandshake),
		rooms:      make(map[string]*Room),
	}
}

// RegisterOperative commits or updates an agent's cryptographic profile into the secure registry.
func (sr *ShadowRegistry) RegisterOperative(id string, identityKey, handshakeKey *ecdsa.PublicKey, incognitoID, codename string) {
	sr.operativesMu.Lock()
	defer sr.operativesMu.Unlock()

	sr.operatives[id] = &Operative{
		ID:           id,
		IdentityKey:  identityKey,
		HandshakeKey: handshakeKey,
		IncognitoID:  incognitoID,
		Codename:     codename,
	}
}

// FetchOperative retrieves an operative's profile from the registry via their unique ID.
func (sr *ShadowRegistry) FetchOperative(id string) (*Operative, bool) {
	sr.operativesMu.RLock()
	defer sr.operativesMu.RUnlock()

	op, exists := sr.operatives[id]
	return op, exists
}

// IssueHandshake stages a volatile, timed challenge nonce for an operative attempting authentication.
func (sr *ShadowRegistry) IssueHandshake(operativeID string, nonce string, validityPeriod time.Duration) {
	sr.handshakesMu.Lock()
	defer sr.handshakesMu.Unlock()

	sr.handshakes[operativeID] = CryptographicHandshake{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(validityPeriod),
	}
}

// InterceptAndConsumeHandshake fetches and immediately destroys an active challenge nonce
// to guarantee single-use forward security (mitigating replay vectors).
func (sr *ShadowRegistry) InterceptAndConsumeHandshake(operativeID string) (CryptographicHandshake, error) {
	sr.handshakesMu.Lock()
	defer sr.handshakesMu.Unlock()

	handshake, found := sr.handshakes[operativeID]
	if !found {
		return CryptographicHandshake{}, ErrHandshakeMissing
	}

	// Immediate destruction ensures the nonce cannot be re-evaluated
	delete(sr.handshakes, operativeID)

	// Validate time constraints before clearing use
	if time.Now().After(handshake.ExpiresAt) {
		return CryptographicHandshake{}, ErrHandshakeMissing
	}

	return handshake, nil
}

// InterceptCodenames returns a slice of operatives whose pseudonyms partially match the fuzzy query.
func (sr *ShadowRegistry) InterceptCodenames(codenameQuery string) []*Operative {
	sr.operativesMu.RLock()
	defer sr.operativesMu.RUnlock()

	var matchedOperatives []*Operative
	for _, op := range sr.operatives {
		if secureContainsIgnoreCase(op.Codename, codenameQuery) {
			matchedOperatives = append(matchedOperatives, op)
		}
	}
	return matchedOperatives
}

// InterceptIdentities returns a slice of operatives whose IDs partially match the fuzzy query string.
func (sr *ShadowRegistry) InterceptIdentities(idQuery string) []*Operative {
	sr.operativesMu.RLock()
	defer sr.operativesMu.RUnlock()

	var matchedOperatives []*Operative
	for _, op := range sr.operatives {
		if secureContainsIgnoreCase(op.ID, idQuery) {
			matchedOperatives = append(matchedOperatives, op)
		}
	}
	return matchedOperatives
}

// secureContainsIgnoreCase normalizes lookup casing for fuzzy matches within the anonymity network.
func secureContainsIgnoreCase(source, target string) bool {
	return strings.Contains(strings.ToLower(source), strings.ToLower(target))
}

// CreateRoom adds a new room to the registry.
func (sr *ShadowRegistry) CreateRoom(id, passphrase, visibility, creatorID string) error {
	sr.roomsMu.Lock()
	defer sr.roomsMu.Unlock()

	if _, exists := sr.rooms[id]; exists {
		return errors.New("room already exists")
	}

	sr.rooms[id] = &Room{
		ID:         id,
		Passphrase: passphrase,
		Visibility: visibility,
		CreatorID:  creatorID,
		Members: map[string]bool{
			creatorID: true,
		},
	}
	return nil
}

// DeleteRoom removes a room from the registry.
func (sr *ShadowRegistry) DeleteRoom(id, creatorID string) error {
	sr.roomsMu.Lock()
	defer sr.roomsMu.Unlock()

	room, exists := sr.rooms[id]
	if !exists {
		return errors.New("room not found")
	}

	if room.CreatorID != creatorID {
		return errors.New("only room creator can delete the room")
	}

	delete(sr.rooms, id)
	return nil
}

// JoinRoom adds a member to a room after verifying the passphrase.
//
// A room must already exist (via CreateRoom) to be joined. Previously this silently
// fabricated a brand-new, member-of-one "phantom" room whenever the target ID wasn't
// found -- e.g. after a server restart wiped the in-memory registry, or a race where a
// client's periodic "re-join my active rooms" call fired before CREATE_ROOM had been
// processed. That meant every client could end up talking to its own disconnected copy
// of a "room" instead of a shared one, which is exactly the kind of silent divergence
// that breaks room membership, message fan-out, and sender-key distribution. Joining a
// room that doesn't exist is now a hard failure so the client can surface it properly.
func (sr *ShadowRegistry) JoinRoom(id, passphrase, operativeID string) (bool, error) {
	sr.roomsMu.Lock()
	room, exists := sr.rooms[id]
	sr.roomsMu.Unlock()

	if !exists {
		return false, errors.New("room not found")
	}

	if room.Passphrase != "" && room.Passphrase != passphrase {
		return false, errors.New("invalid room passphrase")
	}

	if room.Has(operativeID) {
		return false, nil
	}

	room.AddMember(operativeID)
	return true, nil
}

// LeaveRoom removes a member from a room.
func (sr *ShadowRegistry) LeaveRoom(id, operativeID string) error {
	sr.roomsMu.RLock()
	room, exists := sr.rooms[id]
	sr.roomsMu.RUnlock()

	if !exists {
		return errors.New("room not found")
	}

	room.RemoveMember(operativeID)
	return nil
}

// FetchRoom retrieves a room by ID.
func (sr *ShadowRegistry) FetchRoom(id string) (*Room, bool) {
	sr.roomsMu.RLock()
	defer sr.roomsMu.RUnlock()

	room, exists := sr.rooms[id]
	if !exists {
		return nil, false
	}
	return room, true
}

// InterceptPublicRooms returns a slice of public rooms matching the query.
func (sr *ShadowRegistry) InterceptPublicRooms(query string) []*Room {
	sr.roomsMu.RLock()
	defer sr.roomsMu.RUnlock()

	var matches []*Room
	for _, room := range sr.rooms {
		if room.Visibility == "public" && secureContainsIgnoreCase(room.ID, query) {
			matches = append(matches, room)
		}
	}
	return matches
}
