package ws

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"shadow-room-backend/internal/chatpacket"
	"shadow-room-backend/internal/cryptoutil"
	"shadow-room-backend/internal/tickets"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 1 << 20
	sendBufferSize = 256

	guestInfiltrationTimeout = 15 * time.Second
	maxInfiltrationAttempts  = 5
)

// Terminal represents a single live websocket socket connection (an operative's active rig)
// traversing the volatile grid network.
type Terminal struct {
	hub           *Hub
	connection    *websocket.Conn
	egressBuffer  chan []byte
	operativeID   string
	authenticated bool
}

// HandleConnection builds and spins up a full-duplex transmission pump around a new connection.
func HandleConnection(hub *Hub, conn *websocket.Conn) {
	term := &Terminal{
		hub:          hub,
		connection:   conn,
		egressBuffer: make(chan []byte, sendBufferSize),
	}
	go term.writePump()
	go term.readPump()
}

// readPump listens continuously for inbound wire frames arriving from the terminal.
func (t *Terminal) readPump() {
	defer func() {
		if t.authenticated {
			t.hub.Unregister(t)
		}
		_ = t.connection.Close()
	}()

	t.connection.SetReadLimit(maxMessageSize)
	_ = t.connection.SetReadDeadline(time.Now().Add(pongWait))
	t.connection.SetPongHandler(func(string) error {
		return t.connection.SetReadDeadline(time.Now().Add(pongWait))
	})

	// Erase connections failing to authenticate within the designated entry grace period
	infiltrationTimer := time.AfterFunc(guestInfiltrationTimeout, func() {
		if !t.authenticated {
			_ = t.connection.Close()
		}
	})
	defer infiltrationTimer.Stop()

	failedInfiltrations := 0

	for {
		_, rawBytes, err := t.connection.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("shadowroom/telemetry: transport line dropped (%s): %v", t.identityForLog(), err)
			}
			return
		}

		var envelope chatpacket.TransmissionEnvelope
		if err := json.Unmarshal(rawBytes, &envelope); err != nil {
			t.sendCommandFrame("INVALID_PROTOCOL_JSON", "transmitted frame rejected: failed envelope serialization constraint")
			continue
		}

		if !t.authenticated {
			var cmdPayload chatpacket.CommandPayload
			if envelope.Type != "command" {
				t.sendCommandFrame("UNAUTHENTICATED_ACCESS", "access denied: guest lines restricted to command authorization payloads")
				continue
			}

			if err := json.Unmarshal(envelope.Payload, &cmdPayload); err != nil || cmdPayload.Code != "AUTH_REQUEST" {
				t.sendCommandFrame("UNAUTHENTICATED_ACCESS", "access denied: protocol envelope command code must equal AUTH_REQUEST")
				continue
			}

			operativeID, err := t.authenticateInfiltration(cmdPayload)
			if err != nil {
				failedInfiltrations++
				t.sendCommandFrame("AUTHENTICATION_FAILED", err.Error())
				if failedInfiltrations >= maxInfiltrationAttempts {
					log.Printf("shadowroom/telemetry: terminal exceeded threshold infiltration limits, locking gate")
					return
				}
				continue
			}

			infiltrationTimer.Stop()
			t.operativeID = operativeID
			t.authenticated = true
			t.sendCommandFrame("AUTH_OK", "infiltration successful: identity context synchronized: "+operativeID)
			t.hub.Register(t)
			log.Printf("shadowroom/telemetry: unauthenticated guest upgraded to live operative session: %s", operativeID)
			continue
		}

		// --- Authenticated Routing Pipeline Only ---

		if envelope.Type == "command" {
			var cmdPayload chatpacket.CommandPayload
			if err := json.Unmarshal(envelope.Payload, &cmdPayload); err == nil {
				log.Printf("shadowroom/action: [%s] EXEC_CMD code=%s targetID=%s operative=%s", time.Now().Format(time.RFC3339Nano), cmdPayload.Code, cmdPayload.TargetID, t.operativeID)
				if cmdPayload.Code == "AUTH_REQUEST" {
					t.sendCommandFrame("AUTH_OK", "already identified inside grid routing table as: "+t.operativeID)
					continue
				}
				if cmdPayload.Code == "SUBSCRIBE_STATUS" {
					if cmdPayload.TargetID != "" {
						t.hub.TapPresence(t.operativeID, cmdPayload.TargetID)
					}
					continue
				}
				if cmdPayload.Code == "UNSUBSCRIBE_STATUS" {
					if cmdPayload.TargetID != "" {
						t.hub.UntapPresence(t.operativeID, cmdPayload.TargetID)
					}
					continue
				}
				if cmdPayload.Code == "CREATE_ROOM" {
					err := t.hub.Registry.CreateRoom(cmdPayload.TargetID, cmdPayload.Passphrase, cmdPayload.Message, t.operativeID)
					if err != nil {
						log.Printf("shadowroom/action: [%s] CREATE_ROOM_FAIL target=%s err=%v", time.Now().Format(time.RFC3339Nano), cmdPayload.TargetID, err)
						t.sendCommandFrame("CREATE_ROOM_FAIL", err.Error())
					} else {
						log.Printf("shadowroom/action: [%s] CREATE_ROOM_OK target=%s creator=%s", time.Now().Format(time.RFC3339Nano), cmdPayload.TargetID, t.operativeID)
						t.sendCommandFrame("CREATE_ROOM_OK", cmdPayload.TargetID)
					}
					continue
				}
				if cmdPayload.Code == "JOIN_ROOM" {
					isNewMember, err := t.hub.Registry.JoinRoom(cmdPayload.TargetID, cmdPayload.Passphrase, t.operativeID)
					if err != nil {
						log.Printf("shadowroom/action: [%s] JOIN_ROOM_FAIL target=%s operative=%s err=%v", time.Now().Format(time.RFC3339Nano), cmdPayload.TargetID, t.operativeID, err)
						t.sendCommandFrame("JOIN_ROOM_FAIL", err.Error())
					} else {
						log.Printf("shadowroom/action: [%s] JOIN_ROOM_OK target=%s operative=%s new=%v", time.Now().Format(time.RFC3339Nano), cmdPayload.TargetID, t.operativeID, isNewMember)
						t.sendCommandFrame("JOIN_ROOM_OK", cmdPayload.TargetID)
						t.hub.handleMemberJoined(cmdPayload.TargetID, t.operativeID, isNewMember)
					}
					continue
				}
				if cmdPayload.Code == "LEAVE_ROOM" {
					err := t.hub.Registry.LeaveRoom(cmdPayload.TargetID, t.operativeID)
					if err == nil {
						log.Printf("shadowroom/action: [%s] LEAVE_ROOM_OK target=%s operative=%s", time.Now().Format(time.RFC3339Nano), cmdPayload.TargetID, t.operativeID)
						t.sendCommandFrame("LEAVE_ROOM_OK", cmdPayload.TargetID)
						t.hub.handleMemberLeft(cmdPayload.TargetID, t.operativeID)
					}
					continue
				}
				if cmdPayload.Code == "DELETE_ROOM" {
					err := t.hub.DeleteRoom(cmdPayload.TargetID, t.operativeID)
					if err != nil {
						t.sendCommandFrame("DELETE_ROOM_FAIL", err.Error())
					} else {
						t.sendCommandFrame("DELETE_ROOM_OK", cmdPayload.TargetID)
					}
					continue
				}
				if cmdPayload.Code == "GET_ROOM_MEMBERS" {
					membersJSON, err := t.hub.getRoomMembersJSON(cmdPayload.TargetID)
					if err != nil {
						t.sendCommandFrame("GET_ROOM_MEMBERS_FAIL", err.Error())
					} else {
						payload := chatpacket.CommandPayload{
							Code:     "ROOM_MEMBERS_LIST",
							Message:  membersJSON,
							TargetID: cmdPayload.TargetID,
						}
						envelope := chatpacket.TransmissionEnvelope{
							ID:      t.hub.generateEntropyID(),
							From:    "node_relay",
							Type:    "command",
							To:      []string{t.operativeID},
							Payload: convertToRawJSON(payload),
						}
						envelope.Stamp()
						serializedFrame, _ := chatpacket.Marshal(&envelope)
						select {
						case t.egressBuffer <- serializedFrame:
						default:
						}
					}
					continue
				}
				// MESSAGE_READ: relay read receipt back to the original sender
				if cmdPayload.Code == "MESSAGE_READ" {
					if cmdPayload.TargetID != "" {
						if _, isRoom := t.hub.Registry.FetchRoom(cmdPayload.TargetID); isRoom {
							t.hub.registerMessageRead(cmdPayload.Message, t.operativeID, cmdPayload.TargetID, cmdPayload.Signature)
						} else {
							readPayload := chatpacket.CommandPayload{
								Code:      "MESSAGE_READ_ACK",
								Message:   cmdPayload.Message, // comma-separated messageIds
								TargetID:  t.operativeID,      // who read the messages
								Signature: cmdPayload.Signature,
							}
							readEnvelope := chatpacket.TransmissionEnvelope{
								ID:      t.hub.generateEntropyID(),
								From:    "node_relay",
								Type:    "command",
								To:      []string{cmdPayload.TargetID},
								Payload: convertToRawJSON(readPayload),
							}
							readEnvelope.Stamp()
							serialized, err := chatpacket.Marshal(&readEnvelope)
							if err == nil {
								t.hub.transmitToRigOnly(cmdPayload.TargetID, serialized)
							}
						}
					}
					continue
				}
				// MESSAGE_DELIVERED: relay delivery receipt back to the original sender
				if cmdPayload.Code == "MESSAGE_DELIVERED" {
					if cmdPayload.TargetID != "" {
						if _, isRoom := t.hub.Registry.FetchRoom(cmdPayload.TargetID); isRoom {
							t.hub.registerMessageDelivered(cmdPayload.Message, t.operativeID, cmdPayload.TargetID, cmdPayload.Signature)
						} else {
							deliveredPayload := chatpacket.CommandPayload{
								Code:      "MESSAGE_DELIVERED_ACK",
								Message:   cmdPayload.Message, // comma-separated messageIds
								TargetID:  t.operativeID,      // who received the messages
								Signature: cmdPayload.Signature,
							}
							deliveredEnvelope := chatpacket.TransmissionEnvelope{
								ID:      t.hub.generateEntropyID(),
								From:    "node_relay",
								Type:    "command",
								To:      []string{cmdPayload.TargetID},
								Payload: convertToRawJSON(deliveredPayload),
							}
							deliveredEnvelope.Stamp()
							serialized, err := chatpacket.Marshal(&deliveredEnvelope)
							if err == nil {
								t.hub.transmitToRigOnly(cmdPayload.TargetID, serialized)
							}
						}
					}
					continue
				}
			}
		}

		if len(envelope.To) == 0 {
			t.sendCommandFrame("MISSING_TARGET_ADDRESS", "routing envelope contains zero target recipient destinations")
			continue
		}

		// Stamp packet origin deterministically to defend against identity spoofing vectors
		envelope.From = t.operativeID
		t.hub.Route(envelope)
	}
}

// authenticateInfiltration decodes and checks the single-use ticket token and signs off on identity clearance.
func (t *Terminal) authenticateInfiltration(cmd chatpacket.CommandPayload) (string, error) {
	if cmd.Additional == nil || cmd.Additional.Ticket == "" || cmd.Additional.Signature == "" {
		return "", errors.New("security constraints violated: handshake parameters missing ticket token or challenge signature")
	}

	authData := cmd.Additional

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Destructively fetch and consume the single-use token from the high-entropy cache vault
	operativeID, err := t.hub.Vault.LiquidateTicket(ctx, authData.Ticket)
	if err != nil {
		return "", tickets.ErrTicketInvalid
	}

	// 2. Fetch the corresponding persistent signature verification parameters from the memory registry
	operativeProfile, ok := t.hub.Registry.FetchOperative(operativeID)
	if !ok {
		return "", errors.New("security profile error: registered record matching token parameters unavailable")
	}

	// 3. Authenticate the ticket signature payload using your structural signature validation pattern
	if !cryptoutil.AuthenticateSignal(operativeProfile.IdentityKey, authData.Ticket, authData.Signature) {
		return "", errors.New("cryptographic constraint mismatch: transmission validation failed against registered signature profile")
	}

	return operativeID, nil
}

// writePump drains outbound bytes out of the egress array and pipes them into the WebSocket wire.
func (t *Terminal) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = t.connection.Close()
	}()

	for {
		select {
		case message, open := <-t.egressBuffer:
			_ = t.connection.SetWriteDeadline(time.Now().Add(writeWait))
			if !open {
				_ = t.connection.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := t.connection.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			_ = t.connection.SetWriteDeadline(time.Now().Add(writeWait))
			if err := t.connection.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// sendCommandFrame structures and injects system command signals back downstream to the operative terminal.
func (t *Terminal) sendCommandFrame(code, message string) {
	payload := chatpacket.CommandPayload{
		Code:    code,
		Message: message,
	}

	envelope := chatpacket.TransmissionEnvelope{
		From:    "node_relay",
		Type:    "command",
		To:      []string{t.operativeID},
		Payload: convertToRawJSON(payload),
	}
	envelope.Stamp()

	serializedFrame, _ := chatpacket.Marshal(&envelope)
	select {
	case t.egressBuffer <- serializedFrame:
	default:
		// Drop frame if egress buffer pipeline encounters structural congestion
	}
}

func (t *Terminal) identityForLog() string {
	if t.operativeID != "" {
		return t.operativeID
	}
	return "anonymous_guest"
}

func convertToRawJSON(v interface{}) json.RawMessage {
	bytes, _ := json.Marshal(v)
	return bytes
}
