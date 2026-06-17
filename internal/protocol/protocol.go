package protocol

import "time"

// SEAM-16 M35 relay protocol constants.
const (
	Version            = "1.0"
	JSONVersion        = "IARELAY10JSON"
	DidWebsSpecVersion = "1.0-trustoverip-draft"
	MinHostnameLen     = 8
	ChunkThreshold     = 64 * 1024
	ChunkSize          = 32 * 1024
	TunnelGapRetry     = 5 * time.Second
	QuarantineDuration = 365 * 24 * time.Hour
	HeartbeatInterval  = 300
	AllocatePerMin     = 10
	InboundPerHostMin  = 60
)

var PathAllowlist = []string{
	"/{aid}/did.json",
	"/{aid}/kel",
	"/{aid}/keri.cesr",
	"/{aid}/oobi",
	"/oobi/{aid}",
	"/.well-known/did-configuration.json",
}