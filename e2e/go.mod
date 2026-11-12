// The end-to-end test of this relay against the Identity Agent core's own
// client. A separate module so the relay itself takes no dependency on the
// core. The core's module path (identity-agent-core) is not fetchable, so it
// is the git submodule third_party/identity-bot, whose pinned commit is a
// tracked file; never a sibling checkout.
module github.com/grapeid/sp-url-relay/e2e

go 1.26.11

require (
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto v0.0.0
	github.com/grapeid/keri-go v0.5.1-0.20261108070129-11308439ee52
	github.com/grapeid/sp-url-relay v0.0.0
	github.com/mr-tron/base58 v1.2.0
	identity-agent-core v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto v0.0.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-acme/lego/v4 v4.35.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/hirochachacha/go-smb2 v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pkg/sftp v1.13.10 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

replace github.com/grapeid/sp-url-relay => ../

replace identity-agent-core => ../third_party/identity-bot/identity-agent-core

replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto => ../third_party/identity-bot/identity-agent-core/relayproto

replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto => ../third_party/identity-bot/identity-agent-core/witnessproto
