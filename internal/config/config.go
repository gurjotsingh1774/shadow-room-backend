package config

import (
	"os"
	"strconv"
	"time"
)

// Environment holds the runtime parameters for the secure Shadow Room node.
// It centralizes network routing and ephemeral handshake validation constraints.
type Environment struct {
	Port         string        // Port the mesh network listener binds to
	AuthSecret   []byte        // Secret key used to verify local cryptographic signatures
	VaultAddress string        // Address of the underlying Redis storage broker
	GridOrigin   string        // Authorized client origin for incoming connections
	HandshakeTTL time.Duration // Lifespan of a volatile WebSocket authorization ticket
}

// InterceptEnvironment extracts configuration values from system variables,
// falling back to safe defaults if the environment is uninitialized.
func InterceptEnvironment() *Environment {
	return &Environment{
		Port:         extractEnv("PORT", "8080"),
		AuthSecret:   []byte(extractEnv("AUTH_SECRET", "shadow-room-fallback-secure-key")),
		VaultAddress: extractEnv("VAULT_ADDRESS", "redis://localhost:6379"),
		GridOrigin:   extractEnv("GRID_ORIGIN", "http://localhost:5173"),
		HandshakeTTL: time.Duration(extractEnvInt("HANDSHAKE_TTL_SECONDS", 60)) * time.Second,
	}
}

// extractEnv reads a string environment variable or falls back to a default value.
func extractEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// extractEnvInt reads an integer environment variable, parsing it securely.
func extractEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if parsedInt, err := strconv.Atoi(value); err == nil {
			return parsedInt
		}
	}
	return fallback
}
