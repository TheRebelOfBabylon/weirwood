/*
Copyright (C) 2015-2018 Lightning Labs and The Lightning Network Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	loopBackAddrs = []string{"localhost", "127.0.0.1", "[::1]"}
)

// TCPResolver is a function signature that resolves an address on a given
// network.
type TCPResolver = func(network, addr string) (*net.TCPAddr, error)

// NormalizeAddresses returns a new slice with all the passed addresses
// normalized with the given default port and all duplicates removed.
func NormalizeAddresses(addrs []string, defaultPort string,
	tcpResolver TCPResolver) ([]net.Addr, error) {

	result := make([]net.Addr, 0, len(addrs))
	seen := map[string]struct{}{}

	for _, addr := range addrs {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, tcpResolver,
		)
		if err != nil {
			return nil, err
		}

		if _, ok := seen[parsedAddr.String()]; !ok {
			result = append(result, parsedAddr)
			seen[parsedAddr.String()] = struct{}{}
		}
	}

	return result, nil
}

// ParseAddressString converts an address in string format to a net.Addr that is
// compatible with bitswarmd. UDP is not supported because bitswarmd needs reliable
// connections. We accept a custom function to resolve any TCP addresses so
// that caller is able control exactly how resolution is performed.
func ParseAddressString(strAddress string, defaultPort string,
	tcpResolver TCPResolver) (net.Addr, error) {

	var parsedNetwork, parsedAddr string

	// Addresses can either be in network://address:port format,
	// network:address:port, address:port, or just port. We want to support
	// all possible types.
	if strings.Contains(strAddress, "://") {
		parts := strings.Split(strAddress, "://")
		parsedNetwork, parsedAddr = parts[0], parts[1]
	} else if strings.Contains(strAddress, ":") {
		parts := strings.Split(strAddress, ":")
		parsedNetwork = parts[0]
		parsedAddr = strings.Join(parts[1:], ":")
	}

	// Only TCP and Unix socket addresses are valid. We can't use IP or
	// UDP only connections for anything we do in lnd.
	switch parsedNetwork {
	case "unix", "unixpacket":
		return net.ResolveUnixAddr(parsedNetwork, parsedAddr)

	case "tcp", "tcp4", "tcp6":
		return tcpResolver(
			parsedNetwork, verifyPort(parsedAddr, defaultPort),
		)

	case "ip", "ip4", "ip6", "udp", "udp4", "udp6", "unixgram":
		return nil, fmt.Errorf("only TCP or unix socket "+
			"addresses are supported: %s", parsedAddr)

	default:
		// We'll now possibly apply the default port, use the local
		// host short circuit, or parse out an all interfaces listen.
		addrWithPort := verifyPort(strAddress, defaultPort)
		rawHost, _, _ := net.SplitHostPort(addrWithPort)

		// Otherwise, we'll attempt the resolve the host. The Tor
		// resolver is unable to resolve local or IPv6 addresses, so
		// we'll use the system resolver instead.
		if rawHost == "" || IsLoopback(rawHost) ||
			isIPv6Host(rawHost) {

			return net.ResolveTCPAddr("tcp", addrWithPort)
		}

		// If we've reached this point, then it's possible that this
		// resolve returns an error if it isn't able to resolve the
		// host. For eaxmple, local entries in /etc/hosts will fail to
		// be resolved by Tor. In order to handle this case, we'll fall
		// back to the normal system resolver if we fail with an
		// identifiable error.
		addr, err := tcpResolver("tcp", addrWithPort)
		if err != nil {
			torErrStr := "tor host is unreachable"
			if strings.Contains(err.Error(), torErrStr) {
				return net.ResolveTCPAddr("tcp", addrWithPort)
			}

			return nil, err
		}

		return addr, nil
	}
}

// isIPv6Host returns true if the host is IPV6 and false otherwise.
func isIPv6Host(host string) bool {
	v6Addr := net.ParseIP(host)
	if v6Addr == nil {
		return false
	}

	// The documentation states that if the IP address is an IPv6 address,
	// then To4() will return nil.
	return v6Addr.To4() == nil
}

// IsLoopback returns true if an address describes a loopback interface.
func IsLoopback(addr string) bool {
	for _, loopback := range loopBackAddrs {
		if strings.Contains(addr, loopback) {
			return true
		}
	}

	return false
}

// IsUnix returns true if an address describes an Unix socket address.
func IsUnix(addr net.Addr) bool {
	return strings.HasPrefix(addr.Network(), "unix")
}

// verifyPort makes sure that an address string has both a host and a port. If
// there is no port found, the default port is appended. If the address is just
// a port, then we'll assume that the user is using the short cut to specify a
// localhost:port address.
func verifyPort(address string, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If the address itself is just an integer, then we'll assume
		// that we're mapping this directly to a localhost:port pair.
		// This ensures we maintain the legacy behavior.
		if _, err := strconv.Atoi(address); err == nil {
			return net.JoinHostPort("localhost", address)
		}

		// Otherwise, we'll assume that the address just failed to
		// attach its own port, so we'll use the default port. In the
		// case of IPv6 addresses, if the host is already surrounded by
		// brackets, then we'll avoid using the JoinHostPort function,
		// since it will always add a pair of brackets.
		if strings.HasPrefix(address, "[") {
			return address + ":" + defaultPort
		}
		return net.JoinHostPort(address, defaultPort)
	}

	// In the case that both the host and port are empty, we'll use the
	// default port.
	if host == "" && port == "" {
		return ":" + defaultPort
	}

	return address
}

// ClientAddressDialer creates a gRPC dialer that can also dial unix socket
// addresses instead of just TCP addresses.
func ClientAddressDialer(defaultPort string) func(context.Context,
	string) (net.Conn, error) {

	return func(ctx context.Context, addr string) (net.Conn, error) {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, net.ResolveTCPAddr,
		)
		if err != nil {
			return nil, err
		}

		d := net.Dialer{}
		return d.DialContext(
			ctx, parsedAddr.Network(), parsedAddr.String(),
		)
	}
}
