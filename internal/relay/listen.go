package relay

import (
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Listen opens a TCP listener. With proxyProtocol, every connection must open
// with a PROXY protocol header from the platform's TCP proxy, and its remote
// address becomes the client's, so the relay's per-address limits apply to
// clients rather than to the proxy. The header is required, not optional, so
// a client that reaches the relay directly cannot claim an address of its own.
func Listen(addr string, proxyProtocol bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil || !proxyProtocol {
		return ln, err
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: 10 * time.Second,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}, nil
}
