package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big" // Pointing to your updated db package
	"shadow-room-backend/internal/platform/memstore"
	"shadow-room-backend/internal/tickets" // Pointing to your tickets package
)

// JSONWebKeyPublic reflects the standard JWK wire format used by clients (operatives)
// transmitting their raw public keys to the node across the mesh network.
type JSONWebKeyPublic struct {
	KeyType string `json:"kty"` // Key type (e.g., "EC")
	Curve   string `json:"crv"` // Curve parameter (e.g., "P-256")
	XCoord  string `json:"x"`   // Base64RawURL encoded X coordinate
	YCoord  string `json:"y"`   // Base64RawURL encoded Y coordinate
}

// InfiltrationAuthHandler coordinates authentication challenges, ticket issuance,
// and identity mapping for incoming operative handshakes.
type InfiltrationAuthHandler struct {
	Registry *memstore.ShadowRegistry
	Tickets  *tickets.HandshakeVault
}

// ExtractPublicKeyToPEM serializes an operative's ECDSA public identity key into
// a traditional, human-readable PEM block string configuration.
func ExtractPublicKeyToPEM(publicKey *ecdsa.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// ParseJWKToIdentityKey translates a JWK structured network payload into a mathematical
// ecdsa.PublicKey object capable of performing cryptographic signature validation.
func ParseJWKToIdentityKey(jwk JSONWebKeyPublic) (*ecdsa.PublicKey, error) {
	xBytes, errX := base64.RawURLEncoding.DecodeString(jwk.XCoord)
	yBytes, errY := base64.RawURLEncoding.DecodeString(jwk.YCoord)
	if errX != nil || errY != nil {
		return nil, fmt.Errorf("shadowroom/crypto: malformed key coordinate encodings")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(), // Standardizing on the P-256 curve configuration
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// ConvertPublicKeyToJWK serializes an ecdsa.PublicKey into JSONWebKeyPublic format.
func ConvertPublicKeyToJWK(key *ecdsa.PublicKey) JSONWebKeyPublic {
	if key == nil {
		return JSONWebKeyPublic{}
	}
	// X and Y are big.Int. Base64 URL-safe encode coordinates
	// Standard P-256 coordinates are 32 bytes
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)

	xKeyBytes := key.X.Bytes()
	yKeyBytes := key.Y.Bytes()

	copy(xBytes[32-len(xKeyBytes):], xKeyBytes)
	copy(yBytes[32-len(yKeyBytes):], yKeyBytes)

	return JSONWebKeyPublic{
		KeyType: "EC",
		Curve:   "P-256",
		XCoord:  base64.RawURLEncoding.EncodeToString(xBytes),
		YCoord:  base64.RawURLEncoding.EncodeToString(yBytes),
	}
}
