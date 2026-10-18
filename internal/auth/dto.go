package auth

import "shadow-room-backend/internal/cryptoutil"

// InfiltrationRegisterRequest defines the network inbound package layout
// containing an operative's long-term key pairs for system enrollment.
type InfiltrationRegisterRequest struct {
	IdentityKey  cryptoutil.JSONWebKeyPublic `json:"identityPublic"`  // Formally ecdsaPublic: Used for cryptographic signing & verification
	HandshakeKey cryptoutil.JSONWebKeyPublic `json:"handshakePublic"` // Formally ecdhPublic: Used for E2EE key agreement handshakes
}

// ChallengeIssuanceRequest structures the identity tag query parameters
// needed to trigger a volatile authentication nonce from the node.
type ChallengeIssuanceRequest struct {
	OperativeID string `json:"operativeId"` // Formally userId
}

// ChallengeVerificationRequest structures the response payload containing
// the operative's signature proof over the issued system nonce challenge.
type ChallengeVerificationRequest struct {
	OperativeID  string `json:"operativeId"` // Formally userId
	SignatureB64 string `json:"signature"`   // Base64 standard raw 64-byte IEEE P1363 [R || S] coordinate set
}

// OperativeProfileResponse models the structural profile details returned
// during registry discovery operations or directory sweeps.
type OperativeProfileResponse struct {
	ID           string                       `json:"id"`                     // Cryptographic alias profile identifier
	Codename     string                       `json:"codename"`               // Formally userName: User-defined pseudonym within the mesh network
	IncognitoID  string                       `json:"incognitoId"`            // Formally avatarID: Visual/avatar tracking identifier
	IdentityKey  string                       `json:"identityKey,omitempty"`  // Formally publicKey: Human-readable PEM format signing identity public key
	HandshakeKey string                       `json:"handshakeKey,omitempty"` // Formally ecdhPublicKey: Human-readable PEM format E2EE negotiation key
	IdentityJWK  *cryptoutil.JSONWebKeyPublic `json:"identityJWK,omitempty"`
	HandshakeJWK *cryptoutil.JSONWebKeyPublic `json:"handshakeJWK,omitempty"`
	IsRoom       bool                         `json:"isRoom,omitempty"`       // Flag indicating if this is a secure room identity rather than an operative
}
