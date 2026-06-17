package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type chunkAcc struct {
	res   ResponseFrame
	parts []string
}

type Session struct {
	EnrollmentAID string
	Conn          *websocket.Conn
	send          chan []byte
	pending       map[string]chan ResponseFrame
	chunks        map[string]*chunkAcc
	mu            sync.Mutex
}

type Hub struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewHub() *Hub {
	return &Hub{sessions: make(map[string]*Session)}
}

func (h *Hub) Register(enrollmentAID string, conn *websocket.Conn) *Session {
	s := &Session{
		EnrollmentAID: enrollmentAID,
		Conn:          conn,
		send:          make(chan []byte, 32),
		pending:       make(map[string]chan ResponseFrame),
		chunks:        make(map[string]*chunkAcc),
	}
	h.mu.Lock()
	if old, ok := h.sessions[enrollmentAID]; ok {
		_ = old.Conn.Close()
	}
	h.sessions[enrollmentAID] = s
	h.mu.Unlock()
	go s.writePump()
	go s.readPump(h)
	return s
}

func (h *Hub) Unregister(enrollmentAID string) {
	h.mu.Lock()
	delete(h.sessions, enrollmentAID)
	h.mu.Unlock()
}

func (h *Hub) SessionForEnrollment(enrollmentAID string) (*Session, bool) {
	h.mu.RLock()
	s, ok := h.sessions[enrollmentAID]
	h.mu.RUnlock()
	return s, ok
}

func (s *Session) Forward(req RequestFrame, timeout time.Duration) (ResponseFrame, error) {
	ch := make(chan ResponseFrame, 1)
	s.mu.Lock()
	s.pending[req.StreamID] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, req.StreamID)
		s.mu.Unlock()
	}()

	raw, err := json.Marshal(req)
	if err != nil {
		return ResponseFrame{}, err
	}
	select {
	case s.send <- raw:
	case <-time.After(timeout):
		return ResponseFrame{}, fmt.Errorf("tunnel send timeout")
	}

	select {
	case res := <-ch:
		return res, nil
	case <-time.After(timeout):
		return ResponseFrame{}, fmt.Errorf("tunnel response timeout")
	}
}

func (s *Session) readPump(h *Hub) {
	defer func() {
		h.Unregister(s.EnrollmentAID)
		_ = s.Conn.Close()
	}()
	for {
		_, msg, err := s.Conn.ReadMessage()
		if err != nil {
			return
		}
		var kind struct {
			T string `json:"t"`
		}
		if err := json.Unmarshal(msg, &kind); err != nil {
			continue
		}
		switch kind.T {
		case "res":
			var res ResponseFrame
			if err := json.Unmarshal(msg, &res); err != nil {
				continue
			}
			s.deliverResponse(res)
		case "res_chunk":
			var res ResponseFrame
			if err := json.Unmarshal(msg, &res); err != nil {
				continue
			}
			s.accumulateChunk(res)
		case "pong":
		case "err":
		}
	}
}

func (s *Session) writePump() {
	for msg := range s.send {
		_ = s.Conn.WriteMessage(websocket.TextMessage, msg)
	}
}

func (s *Session) deliverResponse(res ResponseFrame) {
	s.mu.Lock()
	ch, ok := s.pending[res.StreamID]
	s.mu.Unlock()
	if ok {
		select {
		case ch <- res:
		default:
		}
	}
}

func (s *Session) accumulateChunk(res ResponseFrame) {
	s.mu.Lock()
	acc, ok := s.chunks[res.StreamID]
	if !ok {
		acc = &chunkAcc{res: res}
		s.chunks[res.StreamID] = acc
	}
	acc.parts = append(acc.parts, res.BodyB64)
	if res.Final {
		body := strings.Join(acc.parts, "")
		raw, _ := base64.RawURLEncoding.DecodeString(body)
		final := acc.res
		final.BodyB64 = base64.RawURLEncoding.EncodeToString(raw)
		final.Final = true
		delete(s.chunks, res.StreamID)
		ch, ok := s.pending[res.StreamID]
		s.mu.Unlock()
		if ok {
			select {
			case ch <- final:
			default:
			}
		}
		return
	}
	s.mu.Unlock()
}