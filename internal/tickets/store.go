package tickets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrTicketInvalid is returned when an infiltration ticket is missing, altered, expired, or intercepted.
var ErrTicketInvalid = errors.New("shadowroom/tickets: infiltration credential void or previously liquidated")

// HandshakeVault manages the single-use authorization lifecycle for establishing stable WebSocket sessions.
//
// These credentials are intentionally decoupled from structural state (like JWTs). They consist
// entirely of 256 bits of high-entropy secure noise. The client cannot reverse-engineer them;
// they serve purely as an opaque marker that maps directly to an operative's ID inside the database layer.
type HandshakeVault struct {
	client *redis.Client
	ttl    time.Duration
}

// NewHandshakeVault instantiates a storage engine for staging ephemeral entry tickets.
func NewHandshakeVault(client *redis.Client, ticketLifespan time.Duration) *HandshakeVault {
	return &HandshakeVault{
		client: client,
		ttl:    ticketLifespan,
	}
}

// buildTicketKey binds a raw token to its isolated storage namespace within the data broker.
func buildTicketKey(token string) string {
	return "wsticket:" + token
}

// MintInfiltrationTicket generates a high-entropy, opaque ticket bound exclusively to an operative's ID.
// It purposefully caches no extra session metadata. This ensures that when the socket upgrades and checks
// the registry, it reads the absolute latest public key definitions on file rather than stale snapshots.
func (hv *HandshakeVault) MintInfiltrationTicket(ctx context.Context, operativeID string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	if err := hv.client.Set(ctx, buildTicketKey(token), operativeID, hv.ttl).Err(); err != nil {
		return "", err
	}
	return token, nil
}

// LiquidateTicket performs a destructive atomic check-and-burn on an incoming credentials token.
// Leveraging Redis's primitive GETDEL, the fetch and removal are compressed into an indivisible state shift.
// If two racing connections attempt to negotiate entry using the same string, one will instantly clear out,
// guaranteeing strict single-use forward security.
func (hv *HandshakeVault) LiquidateTicket(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrTicketInvalid
	}

	operativeID, err := hv.client.GetDel(ctx, buildTicketKey(token)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrTicketInvalid
		}
		return "", err
	}

	return operativeID, nil
}
