package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ecdsaSignatureASN1 models the structural decoding format for ASN.1 DER-encoded signatures.
type ecdsaSignatureASN1 struct {
	R *big.Int
	S *big.Int
}

// DecryptAndParseSignature handles pulling apart signature coordinates (R, S).
// It safely handles both raw 64-byte IEEE P1363 concatenations [R || S] and standard ASN.1 DER encodings.
func DecryptAndParseSignature(signatureBytes []byte) (*big.Int, *big.Int, error) {
	// 1. Evaluate flat IEEE P1363 concatenations (fixed 64-byte payload size)
	if len(signatureBytes) == 64 {
		return new(big.Int).SetBytes(signatureBytes[:32]), new(big.Int).SetBytes(signatureBytes[32:]), nil
	}

	// 2. Fall back to evaluating traditional ASN.1 DER encodings
	var parsedSignature ecdsaSignatureASN1
	if _, err := asn1.Unmarshal(signatureBytes, &parsedSignature); err != nil {
		return nil, nil, fmt.Errorf("shadowroom/crypto: failed to unmarshal ASN1 sequence: %w", err)
	}
	if parsedSignature.R == nil || parsedSignature.S == nil {
		return nil, nil, fmt.Errorf("shadowroom/crypto: signature components contain null parameters")
	}

	return parsedSignature.R, parsedSignature.S, nil
}

// AuthenticateSignal verifies that a transmitted message was signed by the private key
// corresponding to the operative's public identity key, ensuring absolute non-repudiation.
// The signature payload can be formatted as either raw 64-byte chunks or ASN.1 DER sequences.
func AuthenticateSignal(identityKey *ecdsa.PublicKey, cleartextMessage string, base64Signature string) bool {
	if identityKey == nil {
		return false
	}

	// 1. Decode the base64-encoded signature packet coming from the wire
	signatureBytes, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return false
	}

	// 2. Fragment the signature payload into math coordinate integers (R, S)
	r, s, err := DecryptAndParseSignature(signatureBytes)
	if err != nil {
		return false
	}

	// 3. Hash the cleartext message locally to generate the baseline integrity digest
	messageDigest := sha256.Sum256([]byte(cleartextMessage))

	// 4. cryptographically cross-verify the signature authenticity against the public identity key
	return ecdsa.Verify(identityKey, messageDigest[:], r, s)
}
