package protocol

import "time"

// SEAM-16 M35 relay protocol constants.
const (
	// 1.1 moves the allocation token from a subdomain into the first path
	// segment. That changes the wire shape of public_url / public_hostname and
	// the descriptor's token fields, so it is not a 1.0 relay — clients must be
	// able to tell the two apart. See docs/amendments/seam-16-a1-path-tokens.md.
	Version            = "1.1"
	JSONVersion        = "IARELAY11JSON"

	// URLForm tells clients how to build a public URL: "path" means
	// https://<apex>/<token>/..., "subdomain" meant https://<token>.<apex>/...
	URLForm = "path"
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