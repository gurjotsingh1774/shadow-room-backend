package chatpacket

import (
	"encoding/json"
	"shadow-room-backend/internal/cryptoutil"
	"time"
)

// ============================================================================
// LAYER 1: TRANSMISSION ROUTING LAYER
// ============================================================================

// TransmissionEnvelope dictates the structural routing parameters for any packet
// traversing the Shadow Room grid network. Command instructions utilize Type = "command",
// directing the router to decode the internal data stream via CommandPayload.
type TransmissionEnvelope struct {
	ID        string          `json:"id"`                  // Unique verification tracker ID
	From      string          `json:"from,omitempty"`      // Identity stamped by the grid relay node
	To        []string        `json:"to"`                  // Target collection of recipient operatives
	Type      string          `json:"type"`                // Protocol mode: "command" or application-defined signal types
	Payload   json.RawMessage `json:"payload,omitempty"`   // Volatile opaque packet content layer
	Timestamp int64           `json:"timestamp,omitempty"` // Unix epoch record in milliseconds
}

// CommandPayload structures administrative signals and control flow directions
// across established client connections.
type CommandPayload struct {
	Code       string            `json:"code"`                 // Operational command code (e.g., "AUTH_REQ")
	Message    string            `json:"message"`              // System metadata description string
	TargetID   string            `json:"targetId,omitempty"`   // Target user ID for status subscription etc.
	Additional *InfiltrationAuth `json:"additional,omitempty"` // Contextual parameters for identity challenges
	Signature  string            `json:"signature,omitempty"`  // Base64 ECDSA signature for user-to-user commands
	Passphrase string            `json:"passphrase,omitempty"` // Password/phrase for secure rooms
}

// InfiltrationAuth wraps the cryptographic credentials submitted by an operative
// during the initial transport socket upgrade sequence.
type InfiltrationAuth struct {
	Ticket    string `json:"ticket"`    // High-entropy single-use entry token issued by the node
	Signature string `json:"signature"` // Base64 standard, representing a raw 64-byte IEEE P1363 [R || S] coordinate set
}

// Stamp seals the routing envelope with the current precise node millisecond timestamp.
func (te *TransmissionEnvelope) Stamp() {
	te.Timestamp = time.Now().UnixMilli()
}

// Marshal encodes the transmission routing configuration into an outgoing binary byte array.
func Marshal(te *TransmissionEnvelope) ([]byte, error) {
	return json.Marshal(te)
}

// Unmarshal decodes a raw incoming wire stream into an addressable routing envelope.
func Unmarshal(raw []byte) (*TransmissionEnvelope, error) {
	var te TransmissionEnvelope
	if err := json.Unmarshal(raw, &te); err != nil {
		return nil, err
	}
	return &te, nil
}

// ============================================================================
// LAYER 2: PROTECTED APP CONTENT LAYER
// ============================================================================

// SecretPayload contains fully isolated End-to-End Encrypted (E2EE) traffic (e.g., type: "secure_signal").
// The host node transmits this structural unit completely blind to the contents of the text string.
type SecretPayload struct {
	From        OperativeOrigin         `json:"from"`           // Verified provenance of the source node
	ContentType string                  `json:"contentType"`    // Structural schema type identifier
	Encryption  CryptographicParameters `json:"encryption"`     // Cipher parameters required to lock down the contents
	Ciphertext  string                  `json:"ciphertext"`     // Base64 standard string containing the encrypted content
	Signature   SignalSignature         `json:"sig"`            // Absolute non-repudiation origin seal
	Meta        map[string]interface{}  `json:"meta,omitempty"` // Extensible telemetry parameters
}

// OperativeOrigin encapsulates structural context about the originator of a transmission.
type OperativeOrigin struct {
	OperativeID string `json:"operativeId"`          // Cryptographic alias profile identifier
	TerminalID  string `json:"terminalId,omitempty"` // Volatile device identifier configuration
}

// CryptographicParameters defines the mathematical configuration used by operatives
// to encapsulate their secret traffic.
type CryptographicParameters struct {
	Algorithm          string                       `json:"alg"`                          // Cipher identifier (e.g., "AES-GCM-256")
	IV                 string                       `json:"iv"`                           // Base64 standard initialization vector string
	EphemeralPublicKey *cryptoutil.JSONWebKeyPublic `json:"ephemeralPublicKey,omitempty"` // Volatile public agreement component
	KeyID              string                       `json:"keyId,omitempty"`              // Pre-shared key identifier reference
}

// SignalSignature maintains mathematical non-repudiation parameters verifying content source integrity.
type SignalSignature struct {
	Algorithm string `json:"alg"`   // Verification architecture profile (e.g., "ECDSA-P256-SHA256")
	Value     string `json:"value"` // Base64 standard representation of a raw 64-byte [R || S] layout configuration
}

// ExtractSecretPayload deserializes the opaque binary body from an envelope into an addressable application layer schema.
func ExtractSecretPayload(te *TransmissionEnvelope) (*SecretPayload, error) {
	var sp SecretPayload
	if err := json.Unmarshal(te.Payload, &sp); err != nil {
		return nil, err
	}
	return &sp, nil
}
