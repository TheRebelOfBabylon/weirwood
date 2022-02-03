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
	"net"
	"testing"
)

type testingAddress struct {
	address         string
	expectedNetwork string
	expectedAddress string
	isLoopback      bool
	isUnix          bool
}

var (
	defaultTestPort = "1234"
	addressesToTest = []testingAddress{
		{"tcp://127.0.0.1:9735", "tcp", "127.0.0.1:9735", true, false},
		{"tcp:127.0.0.1:9735", "tcp", "127.0.0.1:9735", true, false},
		{"127.0.0.1:9735", "tcp", "127.0.0.1:9735", true, false},
		{":9735", "tcp", ":9735", false, false},
		{"", "tcp", ":1234", false, false},
		{":", "tcp", ":1234", false, false},
		{"tcp4://127.0.0.1:9735", "tcp", "127.0.0.1:9735", true, false},
		{"tcp4:127.0.0.1:9735", "tcp", "127.0.0.1:9735", true, false},
		{"127.0.0.1", "tcp", "127.0.0.1:1234", true, false},
		{"[::1]", "tcp", "[::1]:1234", true, false},
		{"::1", "tcp", "[::1]:1234", true, false},
		{"tcp6://::1", "tcp", "[::1]:1234", true, false},
		{"tcp6:::1", "tcp", "[::1]:1234", true, false},
		{"localhost:9735", "tcp", "127.0.0.1:9735", true, false},
		{"localhost", "tcp", "127.0.0.1:1234", true, false},
		{"unix:///tmp/lnd.sock", "unix", "/tmp/lnd.sock", false, true},
		{"unix:/tmp/lnd.sock", "unix", "/tmp/lnd.sock", false, true},
		{"123", "tcp", "127.0.0.1:123", true, false},
	}
	invalidAddresses = []string{
		"some string",
		"://",
		"12.12.12.12.12.12",
	}
)

// TestAddresses ensures that all supported address formats can be parsed and
// normalized correctly.
func TestAddress(t *testing.T) {
	for _, test := range addressesToTest {
		t.Run(test.address, func(t *testing.T) {
			testAddress(t, test)
		})
	}
	for _, invalidAddr := range invalidAddresses {
		t.Run(invalidAddr, func(t *testing.T) {
			testInvalidAddress(t, invalidAddr)
		})
	}
}

// testAddress parses an address from its string representation, and
// asserts that the parsed net.Addr is correct against the given test case.
func testAddress(t *testing.T, test testingAddress) {
	addr := []string{test.address}
	result := make([]net.Addr, 0, len(addr))
	seen := map[string]struct{}{}

	for _, ad := range addr {
		parsedAddr, err := ParseAddressString(ad, defaultTestPort, net.ResolveTCPAddr)
		if err != nil {
			t.Fatalf("Unable to parse address: %v", err)
		}

		if _, ok := seen[parsedAddr.String()]; !ok {
			result = append(result, parsedAddr)
			seen[parsedAddr.String()] = struct{}{}
		}
	}
	if len(addr) == 0 {
		t.Fatalf("No normalized address returned")
	}
	netAddr := result[0]
	validateAddr(t, netAddr, test)
}

// testInvalidAddress asserts that parsing the invalidAddr string using
// ParseAddressString results in an error.
func testInvalidAddress(t *testing.T, invalidAddr string) {
	addr := []string{invalidAddr}
	for _, ad := range addr {
		_, err := ParseAddressString(ad, defaultTestPort, net.ResolveTCPAddr)
		if err == nil {
			t.Fatalf("Expected error when parsing: %v", invalidAddr)
		}
	}
}

// validateAddr asserts that an addr parsed by ParseAddressString matches the
// properties expected by its addressTest. In particular, it validates that the
// Network() and String() methods match the expectedNetwork and expectedAddress,
// respectively. Further, we test the IsLoopback and IsUnix detection methods
// against addr and assert that they match the expected values in the test case.
func validateAddr(t *testing.T, addr net.Addr, test testingAddress) {
	t.Helper()
	if addr.Network() != test.expectedNetwork || addr.String() != test.expectedAddress {
		t.Fatalf("Mismatched address: expect %s://%s. received %s://%s", test.expectedNetwork, test.expectedAddress, addr.Network(), addr.String())
	}
	isAddrLoopback := IsLoopback(addr.String())
	if test.isLoopback != isAddrLoopback {
		t.Fatalf("Mismatched loopback detection: expected %v, received %v for address %s", test.isLoopback, isAddrLoopback, test.address)
	}
	isAddrUnix := IsUnix(addr)
	if test.isUnix != isAddrUnix {
		t.Fatalf("Mismatched unix detection: expected %v, received %v for address %s", test.isUnix, isAddrUnix, test.address)
	}
}
