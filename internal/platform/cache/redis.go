package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// VaultBroker manages volatile event routing and encrypted offline message storage
// using a Redis backing instance.
type VaultBroker struct {
	client *redis.Client
	ctx    context.Context
}

func NewVaultBroker(redisURL string) *VaultBroker {
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("shadowroom/vault: failed to parse VAULT_ADDRESS %q: %v", redisURL, err)
	}

	// redis.ParseURL extracts credentials and address from the URL but does NOT
	// automatically enable TLS for the rediss:// scheme. Upstash enforces TLS on
	// all TCP connections, so we must inject TLSConfig manually when the URL uses
	// the secure scheme — otherwise the handshake fails silently and every Redis
	// command returns an error (producing the "token issuance failure" on /ws-ticket).
	tlsEnabled := strings.HasPrefix(redisURL, "rediss://")
	if tlsEnabled {
		opt.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	log.Printf("shadowroom/vault: connecting to Redis broker at %q (TLS=%v)", opt.Addr, tlsEnabled)

	client := redis.NewClient(opt)

	// Eagerly validate the connection on startup so any misconfiguration
	// (wrong password, wrong URL scheme, firewall block) surfaces immediately
	// in Render/Vercel logs rather than silently failing at first ws-ticket call.
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if pingErr := client.Ping(pingCtx).Err(); pingErr != nil {
		log.Fatalf("shadowroom/vault: Redis PING failed — check VAULT_ADDRESS and Upstash credentials: %v", pingErr)
	}
	log.Printf("shadowroom/vault: Redis connection established successfully")

	return &VaultBroker{
		client: client,
		ctx:    context.Background(),
	}
}

// Client exposes the underlying go-redis client instance to satisfy external high-entropy
// cryptographic ticket verification vault integrations without violating package encapsulation.
func (vb *VaultBroker) Client() *redis.Client {
	return vb.client
}

// Close gracefully terminates the connection to the underlying message cache.
func (vb *VaultBroker) Close() error {
	return vb.client.Close()
}

// BroadcastSignal pushes an encrypted packet directly onto an active real-time mesh network channel.
func (vb *VaultBroker) BroadcastSignal(channel string, payload []byte) error {
	return vb.client.Publish(vb.ctx, channel, payload).Err()
}

// --- Dead-Drop Offline Queue Logic ---
//
// When an operative goes offline (disconnects from the grid), their undelivered
// packets are routed to a localized dead-drop queue implemented via a Redis LIST.
// Data is stored at the key pattern "deaddrop:{operativeID}".
//
// An atomic Lua script pulls and destroys the queue elements in a single indivisible
// step, preventing racing connections from forcing a double-delivery or packet leak.

const deaddropTTL = 7 * 24 * time.Hour // Abandoned dead-drops dissolve automatically after 7 days.

// buildDeadDropKey structures the unique namespace for an operative's offline storage.
func buildDeadDropKey(operativeID string) string {
	return "deaddrop:" + operativeID
}

// CacheOfflinePacket pushes an encrypted payload onto the tail of an operative's dead-drop queue.
func (vb *VaultBroker) CacheOfflinePacket(ctx context.Context, operativeID string, payload []byte) error {
	key := buildDeadDropKey(operativeID)

	// Transaction pipeline ensures both insertion and expiry are updated atomic-adjacent
	pipe := vb.client.TxPipeline()
	pipe.RPush(ctx, key, payload)
	pipe.Expire(ctx, key, deaddropTTL)

	_, err := pipe.Exec(ctx)
	return err
}

// atomicEvacuateScript reads and instantly deletes the dead-drop list to guarantee single-delivery.
var atomicEvacuateScript = redis.NewScript(`
local payloads = redis.call('LRANGE', KEYS[1], 0, -1)
if #payloads > 0 then
  redis.call('DEL', KEYS[1])
end
return payloads
`)

// EvacuateDeadDrop retrieves all staged offline payloads and completely flushes the queue
// in a single, isolated operation to maintain complete data integrity.
func (vb *VaultBroker) EvacuateDeadDrop(ctx context.Context, operativeID string) ([][]byte, error) {
	result, err := atomicEvacuateScript.Run(ctx, vb.client, []string{buildDeadDropKey(operativeID)}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	rawElements, ok := result.([]interface{})
	if !ok {
		return nil, nil
	}

	evacuatedPayloads := make([][]byte, 0, len(rawElements))
	for _, element := range rawElements {
		if payloadStr, ok := element.(string); ok {
			evacuatedPayloads = append(evacuatedPayloads, []byte(payloadStr))
		}
	}

	return evacuatedPayloads, nil
}
