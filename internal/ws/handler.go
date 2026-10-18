package ws

import (
	"log"
	"net/http"

	"shadow-room-backend/internal/config"

	"github.com/gorilla/websocket"
)

// InfiltrationSocketHandler acts as the edge firewall and gateway, upgrading inbound
// HTTP authorization handshakes into persistent, full-duplex TCP mesh connection streams.
type InfiltrationSocketHandler struct {
	Hub *Hub
	Env *config.Environment
}

// NewInfiltrationSocketHandler configures a new real-time socket entry-point at the node edge.
func NewInfiltrationSocketHandler(hub *Hub, env *config.Environment) *InfiltrationSocketHandler {
	return &InfiltrationSocketHandler{
		Hub: hub,
		Env: env,
	}
}

// InterceptSocketUpgrader builds a websocket.Upgrader dynamically configured to mirror
// the strict CORS limitations enforced at the node's tactical environment boundary.
func (ish *InfiltrationSocketHandler) InterceptSocketUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,

		// CRITICAL: Acts as the absolute firewall barrier for WebSocket entry.
		CheckOrigin: func(r *http.Request) bool {
			incomingOrigin := r.Header.Get("Origin")
			// Enforces synchronization with the dynamic origin authorized in your environmental configuration
			return incomingOrigin == ish.Env.GridOrigin
		},
	}
}

// ServeGridSocket handles raw network streaming handshakes unconditionally.
//
// Protocol Lifecycle:
//
//	An incoming connection is initially received as an unauthenticated guest.
//	It remains completely isolated from the messaging routing matrix (unable to broadcast
//	or intercept signals) until it issues a valid "command" authentication packet containing
//	a high-entropy single-use ticket as its initial wire transmission.
//
//	Terminals obtain this infiltration credential via POST /api/auth/ws-ticket
//	(which remains fully Guarded by cookie verification middleware) right before spawning the socket.
func (ish *InfiltrationSocketHandler) ServeGridSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := ish.InterceptSocketUpgrader()

	gridConnection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("shadowroom/telemetry: secure grid connection upgrade intercepted and dropped: %v", err)
		return
	}

	// Hand over management of the socket connection directly to the tracking loop layer in this package
	HandleConnection(ish.Hub, gridConnection)
}
