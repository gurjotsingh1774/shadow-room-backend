package auth

import (
	"shadow-room-backend/internal/config"            // Pointing to your updated config package
	"shadow-room-backend/internal/platform/memstore" // Pointing to your updated db package
	"shadow-room-backend/internal/tickets"           // Pointing to your updated tickets package
)

// InfiltrationHandler coordinates authentication challenges, profile synchronization,
// and session token issuance for operatives breaking into the Shadow Room grid.
type InfiltrationHandler struct {
	Registry *memstore.ShadowRegistry // The memory-isolated agent database
	Vault    *tickets.HandshakeVault  // Ephemeral single-use ticket manager
	Env      *config.Environment      // Centralized node security parameters
}

// NewInfiltrationHandler configures a new secure gateway handler for the mesh routing layer.
func NewInfiltrationHandler(registry *memstore.ShadowRegistry, vault *tickets.HandshakeVault, env *config.Environment) *InfiltrationHandler {
	return &InfiltrationHandler{
		Registry: registry,
		Vault:    vault,
		Env:      env,
	}
}
