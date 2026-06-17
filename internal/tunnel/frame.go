package tunnel

// SEAM-16 §4.2 JSON tunnel frames (OQ-1 ratified).
type RequestFrame struct {
	T        string            `json:"t"`
	StreamID string            `json:"stream_id"`
	RAID     string            `json:"raid"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	BodyB64  *string           `json:"body_b64"`
}

type ResponseFrame struct {
	T        string            `json:"t"`
	StreamID string            `json:"stream_id"`
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	BodyB64  string            `json:"body_b64,omitempty"`
	Final    bool              `json:"final,omitempty"`
	Seq      int               `json:"seq,omitempty"`
}

type ErrorFrame struct {
	T        string `json:"t"`
	StreamID string `json:"stream_id,omitempty"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
}

type PingFrame struct {
	T string `json:"t"`
}