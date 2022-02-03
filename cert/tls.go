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
package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/TheRebelOfBabylon/weirwood/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	defaultTLSCertDuration = 14 * 30 * 24 * time.Hour
	endOfTime              = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	serialNumberLimit      = new(big.Int).Lsh(big.NewInt(1), 128)
	tlsCypherSuites        = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
)

// LoadCertificate loads a certificate and it's corresponding private key from PEM files
func LoadCertificate(certPath, keyPath string) (tls.Certificate, *x509.Certificate, error) {
	certData, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	x509Cert, err := x509.ParseCertificate(certData.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return certData, x509Cert, nil
}

// GenCertPair generates a key/cert pair to the input paths.
func GenCertPair(org, certFile, keyFile string, certValidity time.Duration, extraIPAddr []string) error {
	now := time.Now()
	validUntil := now.Add(certValidity)
	if validUntil.After(endOfTime) {
		validUntil = endOfTime
	}
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %s", err)
	}
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	dnsNames := []string{host}
	if host != "localhost" {
		dnsNames = append(dnsNames, "localhost")
	}
	dnsNames = append(dnsNames, "unix", "unixpacket")
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if len(extraIPAddr) > 0 {
		for _, ip := range extraIPAddr {
			ipAddresses = append(ipAddresses, net.ParseIP(ip))
		}
	}
	addIP := func(ipAddr net.IP) {
		for _, ip := range ipAddresses {
			if ip.Equal(ipAddr) {
				return
			}
		}
		ipAddresses = append(ipAddresses, ipAddr)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		ipAddr, _, err := net.ParseCIDR(a.String())
		if err == nil {
			addIP(ipAddr)
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert_template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   host,
		},
		NotBefore:             now.Add(-time.Hour * 24),
		NotAfter:              validUntil,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &cert_template, &cert_template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	certBuf := &bytes.Buffer{}
	err = pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return fmt.Errorf("Failed to encode certificate: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("Unable to encode privkey: %v", err)
	}
	keyBuf := &bytes.Buffer{}
	err = pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return fmt.Errorf("Failed to encode private key: %v", err)
	}
	if _, err = os.OpenFile(certFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0775); err != nil {
		return err
	}
	if err = os.WriteFile(certFile, certBuf.Bytes(), 0755); err != nil {
		return err
	}
	if _, err = os.OpenFile(keyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0775); err != nil {
		return err
	}
	if err = os.WriteFile(keyFile, keyBuf.Bytes(), 0755); err != nil {
		return err
	}
	return nil
}

// TLSConfFromCert returns the default TLS configuration used for a server
func TLSConfFromCert(certData tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certData},
		CipherSuites: tlsCypherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}

// parseNetwork parses the network type of the given address.
func parseNetwork(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	default:
		return addr.Network()
	}
}

// getTLSConfig returns a TLS configuration for the gRPC server and credentials
// and a proxy destination for the REST reverse proxy.
func GetTLSConfig(certPath, keyPath string, extraIPAddr []string) ([]grpc.ServerOption, []grpc.DialOption,
	func(net.Addr) (net.Listener, error), func(), error) {
	if !utils.FileExists(certPath) && !utils.FileExists(keyPath) {
		err := GenCertPair("bitswarmd autogenerated cert", certPath, keyPath, defaultTLSCertDuration, extraIPAddr)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	certData, parsedCert, err := LoadCertificate(certPath, keyPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Check if cert is expired
	if time.Now().After(parsedCert.NotAfter) {
		err := os.Remove(certPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		err = os.Remove(keyPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		err = GenCertPair("bitswarmd autogenerated cert", certPath, keyPath, defaultTLSCertDuration, extraIPAddr)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		certData, _, err = LoadCertificate(certPath, keyPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	tlsCfg := TLSConfFromCert(certData)
	restCreds, err := credentials.NewClientTLSFromFile(certPath, "")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cleanUp := func() {}
	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}
	restDialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(restCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200),
		),
	}
	restListen := func(addr net.Addr) (net.Listener, error) {
		return tls.Listen(parseNetwork(addr), addr.String(), tlsCfg)
	}
	return serverOpts, restDialOpts, restListen, cleanUp, nil
}
