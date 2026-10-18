package ws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"shadow-room-backend/internal/chatpacket"
	"shadow-room-backend/internal/platform/cache"
	"shadow-room-backend/internal/platform/memstore"
	"shadow-room-backend/internal/tickets"
)

// Hub orchestrates the active matrix of currently-connected, AUTHENTICATED terminals
// and dynamically decides, for every single transmission packet, whether to hand it straight
// to a live routing loop or park it inside the durable offline dead-drop cache.
//
// Unauthenticated guest terminals are structurally withheld from this mapping, preventing
// them from receiving or intercepting cross-grid telemetry signals.
type Hub struct {
	mu               sync.RWMutex
	terminals        map[string]*Terminal       // OperativeID -> active network rig socket (authenticated only)
	surveillanceTaps map[string]map[string]bool // TargetOperativeID -> Set of subscriber operative IDs

	// Group/Room receipt trackers. Guarded by receiptMu, which is intentionally a
	// *separate* lock from mu (the terminal registry lock): registerMessageRead/
	// registerMessageDelivered need to hold this lock while calling deliverOrBuffer,
	// which itself acquires mu via getTerminal. Sharing a single lock for both would
	// deadlock the moment a goroutine tried to RLock mu while already holding it for
	// writing (Go's sync.RWMutex is not reentrant).
	receiptMu         sync.Mutex
	messageSenders    map[string]string          // MessageID -> Sender OperativeID
	messageReads      map[string]map[string]bool // MessageID -> Set of OperativeIDs
	messageDeliveries map[string]map[string]bool // MessageID -> Set of OperativeIDs

	Broker   *cache.VaultBroker       // Your updated Redis backend managing volatile event routing and dead-drops
	Vault    *tickets.HandshakeVault  // Direct access to timed entry credentials
	Registry *memstore.ShadowRegistry // Centralized, memory-isolated profile database
}

// NewHub establishes an operational tracking center for managing full-duplex client terminals.
func NewHub(broker *cache.VaultBroker, vault *tickets.HandshakeVault, registry *memstore.ShadowRegistry) *Hub {
	return &Hub{
		terminals:         make(map[string]*Terminal),
		surveillanceTaps:  make(map[string]map[string]bool),
		messageSenders:    make(map[string]string),
		messageReads:      make(map[string]map[string]bool),
		messageDeliveries: make(map[string]map[string]bool),
		Broker:            broker,
		Vault:             vault,
		Registry:          registry,
	}
}

// Register locks an operative's current rig into the active routing pool. If a dual-connection
// is initiated (e.g., a fast reconnect loop on a flickering network line), the stale connection
// is severed and dropped immediately to safeguard absolute sequence authority.
func (h *Hub) Register(t *Terminal) {
	h.mu.Lock()
	if oldTerminal, exists := h.terminals[t.operativeID]; exists && oldTerminal != t {
		close(oldTerminal.egressBuffer)
		_ = oldTerminal.connection.Close()
	}
	h.terminals[t.operativeID] = t
	h.mu.Unlock()

	log.Printf("shadowroom/telemetry: operative synchronized with node routing grid: %s", t.operativeID)
	h.flushBacklog(t)

	// Broadcast user status when registering
	h.BroadcastPresenceTransition(t.operativeID, "online")
}

// Unregister cleanly cuts a terminal line out of the active registry map, ensuring it only kills
// itself if it hasn't already been preemptively overtaken by a newer registration process.
func (h *Hub) Unregister(t *Terminal) {
	h.mu.Lock()
	if currentTerminal, ok := h.terminals[t.operativeID]; ok && currentTerminal == t {
		delete(h.terminals, t.operativeID)
		close(t.egressBuffer)
	}
	h.mu.Unlock()
	log.Printf("shadowroom/telemetry: operative detached from grid interface: %s", t.operativeID)

	// Broadcast user status when unregistering
	h.BroadcastPresenceTransition(t.operativeID, "offline")
	// Clean up user's own status subscriptions so we don't leak memory
	h.DismantleTaps(t.operativeID)
}

// getTerminal pulls a thread-safe read reference out of the active terminal map matrix.
func (h *Hub) getTerminal(operativeID string) (*Terminal, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t, ok := h.terminals[operativeID]
	return t, ok
}

func (h *Hub) Route(envelope chatpacket.TransmissionEnvelope) {
	envelope.Stamp()
	serializedPayload, err := chatpacket.Marshal(&envelope)
	if err != nil {
		log.Printf("shadowroom/routing: [%s] ERROR marshal failure for packet originating from %s: %v", time.Now().Format(time.RFC3339Nano), envelope.From, err)
		return
	}

	log.Printf("shadowroom/routing: [%s] ROUTE Envelope ID=%s Type=%s From=%s To=%v", time.Now().Format(time.RFC3339Nano), envelope.ID, envelope.Type, envelope.From, envelope.To)

	for _, targetOperativeID := range envelope.To {
		if targetOperativeID == "" {
			continue
		}

		// Check if target is a secure Room
		if room, isRoom := h.Registry.FetchRoom(targetOperativeID); isRoom {
			h.receiptMu.Lock()
			h.messageSenders[envelope.ID] = envelope.From
			h.receiptMu.Unlock()

			members := room.Snapshot()
			log.Printf("shadowroom/routing: [%s] ROOM_BROADCAST targetRoom=%s memberCount=%d sender=%s", time.Now().Format(time.RFC3339Nano), targetOperativeID, len(members), envelope.From)
			for _, memberID := range members {
				if memberID == envelope.From {
					continue
				}
				log.Printf("shadowroom/routing: [%s] -> Relay room packet %s to member %s", time.Now().Format(time.RFC3339Nano), envelope.ID, memberID)
				h.deliverOrBuffer(memberID, serializedPayload)
			}
			continue
		}

		// Fallback to normal 1-to-1 routing
		if targetOperativeID == envelope.From {
			continue
		}
		log.Printf("shadowroom/routing: [%s] DIRECT_1TO1 packet=%s from=%s to=%s", time.Now().Format(time.RFC3339Nano), envelope.ID, envelope.From, targetOperativeID)
		h.deliverOrBuffer(targetOperativeID, serializedPayload)
	}
}

// deliverOrBuffer determines if a signal can be pushed downstream instantly or if it requires cold caching.
func (h *Hub) deliverOrBuffer(operativeID string, data []byte) {
	terminal, active := h.getTerminal(operativeID)
	if !active {
		h.persistToOfflineBacklog(operativeID, data)
		return
	}

	select {
	case terminal.egressBuffer <- data:
		// Transmission safely staged within the terminal's individual buffer pipeline
	default:
		// The client's egress loop is experiencing structural congestion. Rather than stalling
		// the shared router pool, we drop the connection line entirely and redirect the stream to storage.
		log.Printf("shadowroom/telemetry: terminal write pipeline congested for %s, severing transport lane and caching signal", operativeID)
		h.Unregister(terminal)
		_ = terminal.connection.Close()
		h.persistToOfflineBacklog(operativeID, data)
	}
}

// persistToOfflineBacklog pushes out-of-band wire payloads safely down into your updated VaultBroker cache layout.
func (h *Hub) persistToOfflineBacklog(operativeID string, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := h.Broker.CacheOfflinePacket(ctx, operativeID, data); err != nil {
		log.Printf("shadowroom/telemetry: fatal durable storage loss: failed to stage packet for offline operative %s: %v", operativeID, err)
	}
}

// flushBacklog sweeps the cold storage repository the instant an operative registers online via EvacuateDeadDrop.
func (h *Hub) flushBacklog(t *Terminal) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backlogSignals, err := h.Broker.EvacuateDeadDrop(ctx, t.operativeID)
	if err != nil {
		log.Printf("shadowroom/telemetry: failed to evacuate dead-drop offline signal matrix for %s: %v", t.operativeID, err)
		t.sendCommandFrame("FLUSH_COMPLETE", "offline backlog extraction complete (error)")
		return
	}

	for _, signalPacket := range backlogSignals {
		select {
		case t.egressBuffer <- signalPacket:
		default:
			// If the terminal immediately locks up during extraction, re-buffer back to security cache
			h.persistToOfflineBacklog(t.operativeID, signalPacket)
		}
	}

	if len(backlogSignals) > 0 {
		log.Printf("shadowroom/telemetry: flushed and delivered %d backlogged signal frame(s) securely from dead-drop to operative %s", len(backlogSignals), t.operativeID)
	}

	t.sendCommandFrame("FLUSH_COMPLETE", "offline backlog extraction complete")
}

func (h *Hub) transmitToRigOnly(operativeID string, data []byte) {
	terminal, active := h.getTerminal(operativeID)
	if !active {
		return
	}

	select {
	case terminal.egressBuffer <- data:
		// Transmission safely staged within the terminal's individual buffer pipeline
	default:
		log.Printf("shadowroom/telemetry: terminal write pipeline congested for %s during status update, severing transport lane", operativeID)
		h.Unregister(terminal)
		_ = terminal.connection.Close()
	}
}

func (h *Hub) BroadcastPresenceTransition(targetID string, status string) {
	h.mu.RLock()
	subs, exists := h.surveillanceTaps[targetID]
	if !exists || len(subs) == 0 {
		h.mu.RUnlock()
		return
	}
	subscriberIDs := make([]string, 0, len(subs))
	for subID := range subs {
		subscriberIDs = append(subscriberIDs, subID)
	}
	h.mu.RUnlock()

	for _, subID := range subscriberIDs {
		payload := chatpacket.CommandPayload{
			Code:     "STATUS_UPDATE",
			Message:  status,
			TargetID: targetID,
		}

		envelope := chatpacket.TransmissionEnvelope{
			ID:      h.generateEntropyID(),
			From:    "node_relay",
			Type:    "command",
			To:      []string{subID},
			Payload: convertToRawJSON(payload),
		}
		envelope.Stamp()

		serializedFrame, err := chatpacket.Marshal(&envelope)
		if err != nil {
			continue
		}
		h.transmitToRigOnly(subID, serializedFrame)
	}
}

func (h *Hub) DismantleTaps(subscriberID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for targetID, subs := range h.surveillanceTaps {
		delete(subs, subscriberID)
		if len(subs) == 0 {
			delete(h.surveillanceTaps, targetID)
		}
	}
}

func (h *Hub) TapPresence(subscriberID, targetID string) {
	h.mu.Lock()
	if h.surveillanceTaps == nil {
		h.surveillanceTaps = make(map[string]map[string]bool)
	}
	if _, exists := h.surveillanceTaps[targetID]; !exists {
		h.surveillanceTaps[targetID] = make(map[string]bool)
	}
	h.surveillanceTaps[targetID][subscriberID] = true
	h.mu.Unlock()

	// Send current status of targetID back to subscriberID immediately
	_, isOnline := h.getTerminal(targetID)
	status := "offline"
	if isOnline {
		status = "online"
	}

	payload := chatpacket.CommandPayload{
		Code:     "STATUS_UPDATE",
		Message:  status,
		TargetID: targetID,
	}

	envelope := chatpacket.TransmissionEnvelope{
		ID:      h.generateEntropyID(),
		From:    "node_relay",
		Type:    "command",
		To:      []string{subscriberID},
		Payload: convertToRawJSON(payload),
	}
	envelope.Stamp()

	serializedFrame, err := chatpacket.Marshal(&envelope)
	if err == nil {
		h.transmitToRigOnly(subscriberID, serializedFrame)
	}
}

func (h *Hub) UntapPresence(subscriberID, targetID string) {
	h.mu.Lock()
	if h.surveillanceTaps != nil {
		if subs, exists := h.surveillanceTaps[targetID]; exists {
			delete(subs, subscriberID)
			if len(subs) == 0 {
				delete(h.surveillanceTaps, targetID)
			}
		}
	}
	h.mu.Unlock()
}

func (h *Hub) generateEntropyID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// DeleteRoom notifies room members and then deletes the room from registry.
func (h *Hub) DeleteRoom(roomID, creatorID string) error {
	room, exists := h.Registry.FetchRoom(roomID)
	if !exists {
		return errors.New("room not found")
	}

	if room.CreatorID != creatorID {
		return errors.New("only room creator can delete the room")
	}

	// 1. Notify members first
	deletedPayload := chatpacket.CommandPayload{
		Code:     "ROOM_DELETED",
		TargetID: roomID,
	}
	deletedEnvelope := chatpacket.TransmissionEnvelope{
		ID:      h.generateEntropyID(),
		From:    "node_relay",
		Type:    "command",
		Payload: convertToRawJSON(deletedPayload),
	}
	deletedEnvelope.Stamp()

	for _, mID := range room.Snapshot() {
		envCopy := deletedEnvelope
		envCopy.To = []string{mID}
		serialized, err := chatpacket.Marshal(&envCopy)
		if err == nil {
			h.deliverOrBuffer(mID, serialized)
		}
	}
	return h.Registry.DeleteRoom(roomID, creatorID)
}

// handleMemberJoined notifies members that someone joined, and tells the new member about existing members.
func (h *Hub) handleMemberJoined(roomID, newMemberID string, isNewMember bool) {
	room, exists := h.Registry.FetchRoom(roomID)
	if !exists {
		return
	}

	// Collect all member IDs
	memberIDs := room.Snapshot()

	// Notify the joining member of all current members in the room
	membersPayload := chatpacket.CommandPayload{
		Code:     "ROOM_MEMBERS",
		Message:  strings.Join(memberIDs, ","),
		TargetID: roomID,
	}
	membersEnvelope := chatpacket.TransmissionEnvelope{
		ID:      h.generateEntropyID(),
		From:    "node_relay",
		Type:    "command",
		To:      []string{newMemberID},
		Payload: convertToRawJSON(membersPayload),
	}
	membersEnvelope.Stamp()
	serializedMembers, err := chatpacket.Marshal(&membersEnvelope)
	if err == nil {
		h.deliverOrBuffer(newMemberID, serializedMembers)
	}

	// Only notify existing members that newMemberID joined if they are a newly added member
	if !isNewMember {
		return
	}

	joinPayload := chatpacket.CommandPayload{
		Code:     "ROOM_MEMBER_JOINED",
		Message:  newMemberID,
		TargetID: roomID,
	}
	joinEnvelope := chatpacket.TransmissionEnvelope{
		ID:      h.generateEntropyID(),
		From:    "node_relay",
		Type:    "command",
		Payload: convertToRawJSON(joinPayload),
	}
	joinEnvelope.Stamp()

	for _, mID := range room.Snapshot() {
		if mID == newMemberID {
			continue
		}
		envCopy := joinEnvelope
		envCopy.To = []string{mID}
		serialized, err := chatpacket.Marshal(&envCopy)
		if err == nil {
			h.deliverOrBuffer(mID, serialized)
		}
	}
}

// handleMemberLeft notifies other members that someone left.
func (h *Hub) handleMemberLeft(roomID, leavingMemberID string) {
	room, exists := h.Registry.FetchRoom(roomID)
	if !exists {
		return
	}

	leftPayload := chatpacket.CommandPayload{
		Code:     "ROOM_MEMBER_LEFT",
		Message:  leavingMemberID,
		TargetID: roomID,
	}
	leftEnvelope := chatpacket.TransmissionEnvelope{
		ID:      h.generateEntropyID(),
		From:    "node_relay",
		Type:    "command",
		Payload: convertToRawJSON(leftPayload),
	}
	leftEnvelope.Stamp()

	for _, mID := range room.Snapshot() {
		envCopy := leftEnvelope
		envCopy.To = []string{mID}
		serialized, err := chatpacket.Marshal(&envCopy)
		if err == nil {
			h.deliverOrBuffer(mID, serialized)
		}
	}
}

// getRoomMembersJSON returns members as a serialized JSON string.
func (h *Hub) getRoomMembersJSON(roomID string) (string, error) {
	room, exists := h.Registry.FetchRoom(roomID)
	if !exists {
		return "", errors.New("room not found")
	}

	type MemberInfo struct {
		ID          string `json:"id"`
		Codename    string `json:"codename"`
		IncognitoID string `json:"incognitoId"`
	}

	var infos []MemberInfo
	for _, mID := range room.Snapshot() {
		op, found := h.Registry.FetchOperative(mID)
		if found {
			infos = append(infos, MemberInfo{
				ID:          op.ID,
				Codename:    op.Codename,
				IncognitoID: op.IncognitoID,
			})
		}
	}

	data, err := json.Marshal(infos)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// registerMessageRead tracks room message read receipts and updates the sender when all members read.
func (h *Hub) registerMessageRead(messageIDsComma, readerID, roomID, signature string) {
	// NOTE: this must be receiptMu, not mu -- deliverOrBuffer() below calls getTerminal(),
	// which itself takes mu.RLock(). Locking mu here would deadlock the very first time
	// every room member has read a message (since sync.RWMutex isn't reentrant).
	h.receiptMu.Lock()
	defer h.receiptMu.Unlock()

	_, exists := h.Registry.FetchRoom(roomID)
	if !exists {
		return
	}

	msgIDs := strings.Split(messageIDsComma, ",")
	for _, rawMsgID := range msgIDs {
		msgID := strings.TrimSpace(rawMsgID)
		if msgID == "" {
			continue
		}

		senderID, ok := h.messageSenders[msgID]
		if !ok {
			continue
		}

		// Register the reader
		readers, ok := h.messageReads[msgID]
		if !ok {
			readers = make(map[string]bool)
			h.messageReads[msgID] = readers
		}
		readers[readerID] = true

		// Notify the sender that readerID read msgID
		readPayload := chatpacket.CommandPayload{
			Code:     "MESSAGE_READ_ACK",
			Message:  msgID,
			TargetID: readerID,
		}
		readEnvelope := chatpacket.TransmissionEnvelope{
			ID:      h.generateEntropyID(),
			From:    "node_relay",
			Type:    "command",
			To:      []string{senderID},
			Payload: convertToRawJSON(readPayload),
		}
		readEnvelope.Stamp()
		serialized, err := chatpacket.Marshal(&readEnvelope)
		if err == nil {
			h.deliverOrBuffer(senderID, serialized)
		}
	}
}

// registerMessageDelivered tracks room message delivery receipts and updates the sender when all members receive.
func (h *Hub) registerMessageDelivered(messageIDsComma, recipientID, roomID, signature string) {
	// NOTE: receiptMu, not mu -- see comment in registerMessageRead above.
	h.receiptMu.Lock()
	defer h.receiptMu.Unlock()

	_, exists := h.Registry.FetchRoom(roomID)
	if !exists {
		return
	}

	msgIDs := strings.Split(messageIDsComma, ",")
	for _, rawMsgID := range msgIDs {
		msgID := strings.TrimSpace(rawMsgID)
		if msgID == "" {
			continue
		}

		senderID, ok := h.messageSenders[msgID]
		if !ok {
			continue
		}

		// Register the delivery
		deliveries, ok := h.messageDeliveries[msgID]
		if !ok {
			deliveries = make(map[string]bool)
			h.messageDeliveries[msgID] = deliveries
		}
		deliveries[recipientID] = true

		// Notify the sender that recipientID received msgID
		deliveredPayload := chatpacket.CommandPayload{
			Code:     "MESSAGE_DELIVERED_ACK",
			Message:  msgID,
			TargetID: recipientID,
		}
		deliveredEnvelope := chatpacket.TransmissionEnvelope{
			ID:      h.generateEntropyID(),
			From:    "node_relay",
			Type:    "command",
			To:      []string{senderID},
			Payload: convertToRawJSON(deliveredPayload),
		}
		deliveredEnvelope.Stamp()
		serialized, err := chatpacket.Marshal(&deliveredEnvelope)
		if err == nil {
			h.deliverOrBuffer(senderID, serialized)
		}
	}
}
