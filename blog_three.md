# LND Under the Hood Part 3: Securing The API Layer

## Introduction

Welcome to the final part of the *LND Under the Hood* series. In this last part, we will look at how to create TLS certificates as well as macaroons and integrating them in our API.

## Step 11: TLS Config Parameters

For TLS integration, we will work backwards. That is to say, we will modify `Main()` in `bitswarm/bitswarm.go` and then work our way into new files. This will help give you some insight into what it took to disect the code of LND and understand all its moving parts. We are inserting a block of code between the blocks where we start the main `Server` and instantiate `RpcServer`.

```
func Main(interceptor *intercept.Interceptor, server *Server) error {
    // Starting main server
    ...

    // Get TLS config
	server.logger.Info().Msg("Loading TLS configuration...")
	serverOpts, restDialOpts, restListen, cleanUp, err := cert.GetTLSConfig(server.cfg.TLSCertPath, server.cfg.TLSKeyPath, server.cfg.ExtraIPAddr)
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Could not load TLS configuration: %v", err))
		return err
	}
	server.logger.Info().Msg("TLS configuration successfully loaded.")
	defer cleanUp()


    // Instantiating RPC server
    ...
}
```
So, there's a new function called `GetTLSConfig()` from the `cert` package that has not been populated yet. There are also three new `Config` parameters: `TLSCertPath`, `TLSKeyPath` and `ExtraIPAddr`. We will now add these new `Config` parameters to `bitswarm/config.go`

```
import (
    ...
    "gitlab.com/cypher-engineers/bitswarmd/utils"
    ...
)

type Config struct {
	DefaultLogDir  bool     `yaml:"DefaultLogDir"`
	LogFileDir     string   `yaml:"LogFileDir"`
	ConsoleOutput  bool     `yaml:"ConsoleOutput"`
	GrpcPort       int64    `yaml:"GrpcPort"`
	RestPort       int64    `yaml:"RestPort"`
	ExtraIPAddr    []string `yaml:"ExtraIPAddr"` // optional parameter
	TLSCertPath    string
	TLSKeyPath     string
	WSPingInterval time.Duration
	WSPongWait     time.Duration
}

// all default values will be defined here
var (
    default_log_dir = func() string {
		return utils.AppDataDir("bitswarmd", false)
	}
	...
	default_tls_cert_path    string = default_log_dir() + "/tls.cert"
	default_tls_key_path     string = default_log_dir() + "/tls.key"
	default_config                  = func() Config {
		return Config{
			DefaultLogDir:  true,
			LogFileDir:     default_log_dir(),
			ConsoleOutput:  true,
			GrpcPort:       default_grpc_port,
			RestPort:       default_rest_port,
			TLSCertPath:    default_tls_cert_path,
			TLSKeyPath:     default_tls_key_path,
			WSPingInterval: default_ws_ping_interval,
			WSPongWait:     default_ws_pong_wait,
		}
	}
)

// check_yaml_config assigns default values to any empty attributes that were not defined in the yaml file
func check_yaml_config(config Config) Config {
	pv := reflect.ValueOf(&config)
	v := pv.Elem()
	field_names := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		field_name := field_names.Field(i).Name
		switch field_name {
		...
		case "TLSCertPath":
			if f.String() == "" {
				change_field(f, default_tls_cert_path)
				tls_key := v.FieldByName("TLSKeyPath")
				change_field(tls_key, default_tls_key_path)
			}
		case "TLSKeyPath":
			if f.String() == "" {
				change_field(f, default_tls_key_path)
				tls_cert := v.FieldByName("TLSCertPath")
				change_field(tls_cert, default_tls_cert_path)
			}
		}
	}
	return config
}
```
Note that the `ExtraIPAddr` field is needed if you wish to access your API over the internet. The extra IP addresses will be added to the TLS certificate. Now let's populate our `cert` package.

We have also changed our default log directory. To fully implement this change, we also need to create a `appdata.go` file in the `utils` package.
```
/*
ISC License

Copyright (c) 2013-2017 The btcsuite developers
Copyright (c) 2016-2017 The Lightning Network Developers

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
package utils

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

// Ripped from https://github.com/btcsuite/btcutil

// appDataDir returns an operating system specific directory to be used for
// storing application data for an application.  See AppDataDir for more
// details.  This unexported version takes an operating system argument
// primarily to enable the testing package to properly test the function by
// forcing an operating system that is not the currently one.
func appDataDir(goos, appName string, roaming bool) string {
	if appName == "" || appName == "." {
		return "."
	}

	// The caller really shouldn't prepend the appName with a period, but
	// if they do, handle it gracefully by trimming it.
	appName = strings.TrimPrefix(appName, ".")
	appNameUpper := string(unicode.ToUpper(rune(appName[0]))) + appName[1:]
	appNameLower := string(unicode.ToLower(rune(appName[0]))) + appName[1:]

	// Get the OS specific home directory via the Go standard lib.
	var homeDir string
	usr, err := user.Current()
	if err == nil {
		homeDir = usr.HomeDir
	}

	// Fall back to standard HOME environment variable that works
	// for most POSIX OSes if the directory from the Go standard
	// lib failed.
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}

	switch goos {
	// Attempt to use the LOCALAPPDATA or APPDATA environment variable on
	// Windows.
	case "windows":
		// Windows XP and before didn't have a LOCALAPPDATA, so fallback
		// to regular APPDATA when LOCALAPPDATA is not set.
		appData := os.Getenv("LOCALAPPDATA")
		if roaming || appData == "" {
			appData = os.Getenv("APPDATA")
		}

		if appData != "" {
			return filepath.Join(appData, appNameUpper)
		}

	case "darwin":
		if homeDir != "" {
			return filepath.Join(homeDir, "Library",
				"Application Support", appNameUpper)
		}

	case "plan9":
		if homeDir != "" {
			return filepath.Join(homeDir, appNameLower)
		}

	default:
		if homeDir != "" {
			return filepath.Join(homeDir, "."+appNameLower)
		}
	}

	// Fall back to the current directory if all else fails.
	return "."
}

// AppDataDir returns an operating system specific directory to be used for
// storing application data for an application.
//
// The appName parameter is the name of the application the data directory is
// being requested for.  This function will prepend a period to the appName for
// POSIX style operating systems since that is standard practice.  An empty
// appName or one with a single dot is treated as requesting the current
// directory so only "." will be returned.  Further, the first character
// of appName will be made lowercase for POSIX style operating systems and
// uppercase for Mac and Windows since that is standard practice.
//
// The roaming parameter only applies to Windows where it specifies the roaming
// application data profile (%APPDATA%) should be used instead of the local one
// (%LOCALAPPDATA%) that is used by default.
//
// Example results:
//  dir := AppDataDir("myapp", false)
//   POSIX (Linux/BSD): ~/.myapp
//   Mac OS: $HOME/Library/Application Support/Myapp
//   Windows: %LOCALAPPDATA%\Myapp
//   Plan 9: $home/myapp
func AppDataDir(appName string, roaming bool) string {
	return appDataDir(runtime.GOOS, appName, roaming)
}

```
This function is taken from btcsuite and is a OS agnostic way of finding the *AppData* directory or it's equivalent.

## Step 12: TLS Helper Functions

Create a new file called `tls.go` and add the following:
```
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

	"gitlab.com/cypher-engineers/bitswarmd/utils"
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
```
We need to create a helper function in the `utils` package called `FileExists()` for this to work.
`general.go`
```
package utils

import (
	"os"
)

// FileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/lightningnetwork/lnd
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

```
If you look at the last few lines of the `GetTLSConfig()` function, you'll notice we create new REST proxy dial options and a new listener that uses TLS. We can now delete the relevant functions in `auth` for these same REST options as we won't be using them anymore. Other things to note are the `GenCertPair()`, `LoadCertificate()` and `TLSFromCert()` public functions. These serve to create new certificates if none are present as well as load the TLS config from those files. We will need them especially for our CLI.

We are now ready to integrate TLS into our `Main` and CLI Tool.

## Step 13: TLS API/CLI Integeration

In `Main`, make the following changes:
```
func Main() {
    ...
    // Creating gRPC server and Server options
	grpc_interceptor := intercept.NewGrpcInterceptor(rpcServer.logger, false)
	rpcServerOpts := grpc_interceptor.CreateGrpcOptions()
	serverOpts = append(serverOpts, rpcServerOpts...)
	grpc_server := grpc.NewServer(serverOpts...)
	rpcServer.RegisterWithGrpcServer(grpc_server)
    ...
    // Starting REST proxy
	stopProxy, err := startRestProxy(
		server.cfg, rpcServer, restDialOpts, restListen,
	)
	if err != nil {
		return err
	}
	defer stopProxy()
    ...
}
```
We removed the part where we create a blank array of `grpc.DialOption` and removed the `GetRestOptions()` call. Our TLS server side integration is pretty much complete. If we compile and run, we won't be able to use the CLI since we haven't integrated TLS there. We can, however, use either Python or `curl` to test both the gRPC middleware we added in the last part and our TLS integration.
`curl`
```
$ curl -X GET http://localhost:8080/v1/test
Client sent an HTTP request to an HTTPS server.
$ curl -X GET https://localhost:8080/v1/test
curl: (60) SSL certificate problem: self signed certificate
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
$ curl -X GET --cacert ~/Library/Application\ Support/Bitswarmd/tls.cert https://localhost:8080/v1/test
{"msg":"This is a regular test"}$
```
`python`
```
import protos.swarm_pb2 as swarm
import protos.swarm_pb2_grpc as swarmrpc
import grpc
import os

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

cert = open(os.path.expanduser('~/Library/Application\ Support/Bitswarmd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:4567', creds)
stub = swarmrpc.SwarmStub(channel)

response = stub.TestCommand(swarm.TestRequest())
print(response.msg)
```
```
$ python grpc_test.py
This is a regular test
$
```
Let us now move onto the CLI. Open the `connection.go` file in the `auth` package and modify the `GetClientConn()` function as follows:
```
import (
	"fmt"

	"gitlab.com/cypher-engineers/bitswarmd/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200)
)

// GetClientConn returns the grpc Client connection for use in instantiating gRPC Clients
func GetClientConn(grpcServerAddr, grpcServerPort, tlsCertPath string) (*grpc.ClientConn, error) {
	//get TLS credentials from TLS certificate file
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	genericDialer := utils.ClientAddressDialer(grpcServerPort)
	opts = append(opts, grpc.WithContextDialer(genericDialer))
	opts = append(opts, grpc.WithDefaultCallOptions(maxMsgRecvSize))
	conn, err := grpc.Dial(grpcServerAddr+":"+grpcServerPort, opts...)
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to RPC server: %v", err)
	}
	return conn, nil
}
```
And finally we will add a new CLI argument `tlscertpath` and feed this value or it's default if the argument is not specified in `GetClientConn()`.
```
import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli"
	"gitlab.com/cypher-engineers/bitswarmd/auth"
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	"gitlab.com/cypher-engineers/bitswarmd/utils"
)

var (
	defaultRPCAddr         = "localhost"
	defaultRPCPort         = "4567"
	defaultTLSCertFilename = "tls.cert"
	defaultBitswarmdDir    = utils.AppDataDir("bitswarmd", false)
	defaultTLSCertPath     = filepath.Join(defaultBitswarmdDir, defaultTLSCertFilename)
)

type Args struct {
	RPCAddr     string
	RPCPort     string
	TLSCertPath string
}
...
// getSwarmClient returns the SwarmClient instance from the swarmrpc package as well as a cleanup function
func getSwarmClient(ctx *cli.Context) (swarmrpc.SwarmClient, func()) {
	...
	conn, err := auth.GetClientConn(args.RPCAddr, args.RPCPort, args.TLSCertPath)
	...
}

// extractArgs extracts the arguments inputted to the lncli command
func extractArgs(ctx *cli.Context) *Args {
	return &Args{
		RPCAddr:     ctx.GlobalString("rpc_addr"),
		RPCPort:     ctx.GlobalString("rpc_port"),
		TLSCertPath: ctx.GlobalString("tlscertpath"),
	}
}

// main is the entrypoint for swarmcli
func main() {
	app := cli.NewApp()
	app.Name = "swarmcli"
	app.Usage = "Command Line tool for the Bitswarm Daemon (bitswarmd)"
	app.Flags = []cli.Flag{
		...
		cli.StringFlag{
			Name:      "tlscertpath",
			Value:     defaultTLSCertPath,
			Usage:     "The path to bitswarmd's TLS certificate.",
			TakesFile: true,
		},
	}
	app.Commands = []cli.Command{
		stopCommand,
		testCommand,
	}
	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
```
And now if we quickly test our CLI, we should not get any errors.
```
$ swarmcli test
{
    "msg":  "This is a regular test"
}
```

## Step 14: KVDB

Before we get right into creating macaroons, defining permissions, etc. We need a Key-Value Database (KVDB). LND uses `bbolt` and has a dedicated package called `kvdb` for molding `bbolt` to suit the needs of LND. We will simplify this process by creating a `kvdb` package with the file `db.go` and create a simple `DB` struct. The `DB` struct will implement `bbolt.DB` and also have a `sync.RWMutex` attribute to make read/write operations on the database safe for concurrency. In `Main()` we will add the following block of code right before we start the `RpcServer`.
```
import (
	...
	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
	...
)

func Main() {
	...
	// Starting bbolt kvdb
	server.logger.Info().Msg("Opening database...")
	db, err := kvdb.NewDB(server.cfg.MacaroonDBPath)
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize Macaroon DB: %v", err))
		return err
	}
	server.logger.Info().Msg("Database successfully opened.")
	defer db.Close()

	//Starting RPC and gRPC Servers
	err = rpcServer.Start()
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not start RPC server: %v", err))
		return err
	}
	defer rpcServer.Stop()
	...
}
```
Then we will create our `DB` struct in `kvdb/db.go`
```
package kvdb

import (
	"sync"

	bolt "go.etcd.io/bbolt"
)

type DB struct {
	bolt.DB
	PwdMutex sync.RWMutex
}

// NewDB instantiates the bbolt kvdb and returns it along with a RWMutex to make it read/write safe in goroutines
func NewDB(db_path string) (*DB, error) {
	db, err := bolt.Open(db_path, 0755, nil)
	if err != nil {
		return nil, err
	}
	return &DB{
		DB: *db,
	}, nil
}
```
Again, you probably noticed that we need to define yet another `Config` parameter: `MacaroonDBPath`. Here is the new `config.go`.
```
type Config struct {
	DefaultLogDir  bool     `yaml:"DefaultLogDir"`
	LogFileDir     string   `yaml:"LogFileDir"`
	ConsoleOutput  bool     `yaml:"ConsoleOutput"`
	GrpcPort       int64    `yaml:"GrpcPort"`
	RestPort       int64    `yaml:"RestPort"`
	ExtraIPAddr    []string `yaml:"ExtraIPAddr"` // optional parameter
	TLSCertPath    string
	TLSKeyPath     string
	MacaroonDBPath string
	WSPingInterval time.Duration
	WSPongWait     time.Duration
}

// all default values will be defined here
var (
	...
	default_macaroon_db_file string = default_log_dir() + "/macaroon.db"
	default_config                  = func() Config {
		return Config{
			DefaultLogDir:  true,
			LogFileDir:     default_log_dir(),
			ConsoleOutput:  true,
			GrpcPort:       default_grpc_port,
			RestPort:       default_rest_port,
			TLSCertPath:    default_tls_cert_path,
			TLSKeyPath:     default_tls_key_path,
			MacaroonDBPath: default_macaroon_db_file,
			WSPingInterval: default_ws_ping_interval,
			WSPongWait:     default_ws_pong_wait,
		}
	}
)
...

// check_yaml_config assigns default values to any empty attributes that were not defined in the yaml file
func check_yaml_config(config Config) Config {
	pv := reflect.ValueOf(&config)
	v := pv.Elem()
	field_names := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		field_name := field_names.Field(i).Name
		switch field_name {
		...
		case "MacaroonDBPath":
			if f.String() == "" {
				change_field(f, default_macaroon_db_file)
			}
		}
	}
	return config
}
```
We need the KVDB to store our secret keys for securing our macaroons. The KVDB file will store a hashed password. In LND, this password is used to unlock the LND wallet, the macaroon key-store, etc. In Bitswarmd, the password will be solely for unlocking the macaroon key-store. So the next step is to build an unlocker service.

## Step 15: Unlocker Service

The unlocker service is what prompts the user to enter a password in LND when you enter the `lncli unlock` command. We will now implement a similar version of the unlocker service in bitswarmd so that the password can be used to unlock the macaroon key-store (KVDB).

First, we will create new proto and YAML files in `swarmrpc` called `unlocker.proto` and `unlocker.yaml` respectively. We will define three new commands for our unlocker service: `SetPassword()`, `UnlockDaemon()` and `ChangePassword()`.
`unlocker.proto`
```
syntax = "proto3";

package swarmrpc;

option go_package = "gitlab.com/cypher-engineers/bitswarmd/swarmrpc";

// Unlocker is the service for creating, entering and changing passwords for unlocking the macaroon key-store
service Unlocker {
    /* swarmcli: `setpassword`
    SetPassword prompts the user to set a password on first startup if no password has already been set.
    */
    rpc SetPassword (SetPwdRequest) returns (SetPwdResponse);
    /* swarmcli: `unlock`
    UnlockDaemon prompts the user to enter their password if a password has already been set. If not, re-prompts user to set a password
    */
    rpc UnlockDaemon (UnlockRequest) returns (UnlockResponse);
    /* swarmcli: `changepassword`
    ChangePassword prompts the user to enter the current password and enter a new password. If no password has been set, it prompts the user to set one
    */
    rpc ChangePassword (ChangePwdRequest) returns (ChangePwdResponse);
}

message SetPwdRequest {
    bytes password = 1;
    bool stateless_init = 2;
}
message SetPwdResponse {
    bytes admin_macaroon = 1;
}
message UnlockRequest {
    bytes password = 1;
}
message UnlockResponse {
}
message ChangePwdRequest {
    bytes current_password = 1;
    bytes new_password = 2;
    bool stateless_init = 3;
	bool new_macaroon_root_key = 4;
}
message ChangePwdResponse {
    bytes admin_macaroon = 1;
}
```
`unlocker.yaml`
```
type: google.api.Service
config_version: 3

http:
  rules:
    - selector: swarmrpc.Unlocker.SetPassword
      post: "/v1/setpassword"
      body: "*"
    - selector: swarmrpc.Unlocker.UnlockDaemon
      post: "/v1/unlock"
      body: "*"
    - selector: swarmrpc.Unlocker.ChangePassword
      post: "/v1/changepassword"
      body: "*"
```
Here because our commands have input arguments, our REST equivalents must be POST requests instead of simple GETs. `SetPassword()` and `ChangePassword()` return a macaroon in the case that the user requests to start our service as stateless where no macaroon files are created. More on stateless-init later. For now, let's generate the new unlocker stubs and reverse proxy files.
```
$ ./gen_protos.sh -y unlocker.yaml -p unlocker.proto
```

The next step is to define a `UnlockerService` struct in a file called `service.go` in a new package that we will call `unlocker`. Our `UnlockerService` will implement `UnimplementedUnlockerServer`.
```
package unlocker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"

	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

var (
	ErrPasswordAlreadySet = fmt.Errorf("Password has already been set.")
	ErrPasswordNotSet     = fmt.Errorf("Password has not been set.")
	ErrWrongPassword      = fmt.Errorf("Wrong password.")
	ErrUnlockTimeout      = fmt.Errorf("Got no unlock message before timeout")
	pwdKeyBucketName      = []byte("pwdkeys")
	pwdKeyID              = []byte("pwd")
)

type PasswordMsg struct {
	Password      []byte
	StatelessInit bool
	Err           error
}

type UnlockerService struct {
	swarmrpc.UnimplementedUnlockerServer
	PassChan    chan *PasswordMsg
	MacRespChan chan []byte
	macaroonDB  *kvdb.DB
}

// NewUnlockerService creates a new instance of the UnlockerService needed for set passwords, unlocking the macaroon key-store and changing passwords
func NewUnlockerService(db *kvdb.DB) (*UnlockerService, error) {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(pwdKeyBucketName)
		return err
	}); err != nil {
		return nil, err
	}
	return &UnlockerService{
		PassChan:    make(chan *PasswordMsg, 1),
		MacRespChan: make(chan []byte, 1),
		macaroonDB:  db,
	}, nil
}

// RegisterWithGrpcServer registers the gRPC server to the unlocker service
func (u *UnlockerService) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	swarmrpc.RegisterUnlockerServer(grpcServer, u)
	return nil
}

// RegisterWithRestProxy registers the UnlockerService with the REST proxy
func (u *UnlockerService) RegisterWithRestProxy(ctx context.Context, mux *proxy.ServeMux, restDialOpts []grpc.DialOption, restProxyDest string) error {
	err := swarmrpc.RegisterUnlockerHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}
	return nil
}

// setPassword will set the password if one has not already been set
func (u *UnlockerService) setPassword(password []byte, overwrite bool) error {
	u.macaroonDB.PwdMutex.Lock()
	defer u.macaroonDB.PwdMutex.Unlock()
	return u.macaroonDB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(pwdKeyBucketName) // get the password bucket
		if bucket == nil {
			return fmt.Errorf("Password bucket not found")
		}
		pwd := bucket.Get(pwdKeyID) //get the password kv pair
		if len(pwd) > 0 && !overwrite {
			return ErrPasswordAlreadySet
		}
		// no pwd has been set or a new one has been given
		hash := sha256.Sum256(password)
		err := bucket.Put(pwdKeyID, hash[:])
		if err != nil {
			return err
		}
		return nil
	})
}

// readPassword will read the password provided and compare to what's in the db
func (u *UnlockerService) readPassword(password []byte) error {
	u.macaroonDB.PwdMutex.Lock()
	defer u.macaroonDB.PwdMutex.Unlock()
	return u.macaroonDB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(pwdKeyBucketName) // get the password bucket
		if bucket == nil {
			return fmt.Errorf("Password bucket not found")
		}
		pwd := bucket.Get(pwdKeyID) //get the password kv pair
		if len(pwd) == 0 {
			return ErrPasswordNotSet
		}
		// pwd has been set so comparing
		hash := sha256.Sum256(password)
		if !reflect.DeepEqual(hash[:], pwd) {
			return ErrWrongPassword
		}
		return nil
	})
}

// SetPassword will set the password of the kvdb if none has been set
func (u *UnlockerService) SetPassword(ctx context.Context, req *swarmrpc.SetPwdRequest) (*swarmrpc.SetPwdResponse, error) {
	err := u.setPassword(req.Password, false)
	if err != nil {
		return nil, err
	}
	// We can now send the SetPasswordMsg through the channel
	select {
	case u.PassChan <- &PasswordMsg{Password: req.Password, StatelessInit: req.StatelessInit, Err: nil}:
		// We hang until we receive the admin macaroon or a timeout error
		select {
		case adminMac := <-u.MacRespChan:
			return &swarmrpc.SetPwdResponse{
				AdminMacaroon: adminMac,
			}, nil
		case <-ctx.Done():
			return nil, ErrUnlockTimeout
		}

	case <-ctx.Done():
		return nil, ErrUnlockTimeout
	}
}

// UnlockDaemon takes a given password, validates it and unlocks the macaroon key-store if a valid password is provided
func (u *UnlockerService) UnlockDaemon(ctx context.Context, req *swarmrpc.UnlockRequest) (*swarmrpc.UnlockResponse, error) {
	err := u.readPassword(req.Password)
	if err != nil {
		return nil, err
	}
	// We can now send the UnlockMsg through the channel
	select {
	case u.PassChan <- &PasswordMsg{Password: req.Password, Err: nil}:
		// We hang until we receive the admin macaroon or a timeout error
		select {
		case <-u.MacRespChan:
			return &swarmrpc.UnlockResponse{}, nil
		case <-ctx.Done():
			return nil, ErrUnlockTimeout
		}
	case <-ctx.Done():
		return nil, ErrUnlockTimeout
	}
}

// ChangePassword takes the old password, validates it and sets the new password from the inputted new password only if a previous password has been set
func (u *UnlockerService) ChangePassword(ctx context.Context, req *swarmrpc.ChangePwdRequest) (*swarmrpc.ChangePwdResponse, error) {
	// first we check the validaty of the old password
	err := u.readPassword(req.CurrentPassword)
	if err != nil {
		return nil, err
	}
	// Next we set the new password
	err = u.setPassword(req.NewPassword, true)
	if err != nil {
		return nil, err
	}
	// We can now send the UnlockMsg through the channel
	select {
	case u.PassChan <- &PasswordMsg{Password: req.NewPassword, StatelessInit: req.StatelessInit, Err: nil}:
		// We hang until we receive the admin macaroon or a timeout error
		select {
		case adminMac := <-u.MacRespChan:
			return &swarmrpc.ChangePwdResponse{
				AdminMacaroon: adminMac,
			}, nil
		case <-ctx.Done():
			return nil, ErrUnlockTimeout
		}

	case <-ctx.Done():
		return nil, ErrUnlockTimeout
	}
}
```
Our `UnlockerService` has fully implemented the `UnimplementedUnlockerServer` and can be registered with both the gRPC server and REST proxy.

We will now make modificiations to our gRPC middleware. We are going to add a `state` attribute to the `GrpcInterceptor` struct as well as a new unary server interceptor and stream server interceptor. We want to prevent users from trying to set or change the password as well as re-unlock the daemon once it's been unlocked.
```
import (
	...
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	...
)

type rpcState uint8

const (
	daemonLocked rpcState = iota
	daemonUnlocked
)

var (
	// ErrDaemonLocked is returned if the daemon is locked and any service
	// other than the Unlocker is called.
	ErrDaemonLocked = fmt.Errorf("daemon locked, unlock it to enable " +
		"full RPC access")

	// ErrDaemonUnlocked is returned if the Unlocker service is
	// called when the daemon already has been unlocked.
	ErrDaemonUnlocked = fmt.Errorf("daemon already unlocked, " +
		"Unlocker service is no longer available")
)

// GrpcInteceptor struct is a data structure with attributes relevant to creating the gRPC interceptor
type GrpcInterceptor struct {
	state       rpcState
	noMacaroons bool
	log         *zerolog.Logger
	sync.RWMutex
}

// NewGrpcInterceptor instantiates a new GrpcInterceptor struct
func NewGrpcInterceptor(log *zerolog.Logger, noMacaroons bool) *GrpcInterceptor {
	return &GrpcInterceptor{
		state:       daemonLocked,
		noMacaroons: noMacaroons,
		log:         log,
	}
}

// SetDaemonUnlocked moves the RPC state from daemonLocked state to daemonUnlocked state.
func (i *GrpcInterceptor) SetDaemonUnlocked() {
	i.Lock()
	defer i.Unlock()

	i.state = daemonUnlocked
}

// CreateGrpcOptions creates a array of gRPC interceptors
func (i *GrpcInterceptor) CreateGrpcOptions() []grpc.ServerOption {
	...
	// Next we'll add our RPC state check interceptors, that will check
	// whether the attempted call is allowed in the current state.
	unaryInterceptors = append(
		unaryInterceptors, i.rpcStateUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, i.rpcStateStreamServerInterceptor(),
	)
	// Create server options from the interceptors we just set up.
	chainedUnary := grpc_middleware.WithUnaryServerChain(
		unaryInterceptors...,
	)
	chainedStream := grpc_middleware.WithStreamServerChain(
		strmInterceptors...,
	)
	serverOpts := []grpc.ServerOption{chainedUnary, chainedStream}
	return serverOpts
}

// checkRPCState checks whether a call to the given server is allowed in the
// current RPC state.
func (i *GrpcInterceptor) checkRPCState(srv interface{}) error {
	i.RLock()
	state := i.state
	i.RUnlock()

	switch state {
	// If the daemon is locked, only calls to the Unlocker are
	// accepted.
	case daemonLocked:
		_, ok := srv.(swarmrpc.UnlockerServer)
		if !ok {
			return ErrDaemonLocked
		}
	// If the RPC server is active, we allow calls to any
	// service except the Unlocker.
	case daemonUnlocked:
		_, ok := srv.(swarmrpc.UnlockerServer)
		if ok {
			return ErrDaemonUnlocked
		}

	default:
		return fmt.Errorf("unknown RPC state: %v", state)
	}

	return nil
}

// rpcStateUnaryServerInterceptor is a gRPC interceptor that checks whether
// calls to the given gRPC server is allowed in the current rpc state.
func (i *GrpcInterceptor) rpcStateUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		if err := i.checkRPCState(info.Server); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// rpcStateStreamServerInterceptor is a gRPC interceptor that checks whether
// calls to the given gRPC server is allowed in the current rpc state.
func (i *GrpcInterceptor) rpcStateStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		if err := i.checkRPCState(srv); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}
```
Again, this is stuff I copied from LND. It works, so why reinvent the wheel? We can now add some new code to `Main()` in `bitswarm/bitswarm.go`. We will add a `waitForPassword()` function which will hang until a password is received in the `UnlockerService` password channel or if a shutdown request is received. We will also add a temporary line right under the `waitForPassword()` call where we will pass a random byte array into the `UnlockerService` `MacRespChan` channel so that our unlocker service doesn't just hang forever. Later, we will have our macaroon service push an actual macaroon byte array into this channel. Lastly, we want to have our `UnlockerService` initialized and register it with both the gRPC server and the REST proxy.
```
func Main() {
	...
	// Starting kvdb
	server.logger.Info().Msg("Opening database...")
	db, err := kvdb.NewDB(server.cfg.MacaroonDBPath)
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize Macaroon DB: %v", err))
		return err
	}
	server.logger.Info().Msg("Database successfully opened.")
	defer db.Close()

	// Instantiate Unlocker Service and register with gRPC server
	server.logger.Info().Msg("Initializing unlocker service...")
	unlockerService, err := unlocker.NewUnlockerService(db)
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize unlocker service: %v", err))
		return err
	}
	unlockerService.RegisterWithGrpcServer(grpc_server)
	server.logger.Info().Msg("Unlocker service initialized.")

	//Starting RPC and gRPC Servers
	err = rpcServer.Start()
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not start RPC server: %v", err))
		return err
	}
	defer rpcServer.Stop()

	// start gRPC listening
	err = startGrpcListen(grpc_server, rpcServer.Listener)
	if err != nil {
		rpcServer.logger.Fatal().Msg(fmt.Sprintf("Could not start gRPC listen on %v:%v", rpcServer.Listener.Addr(), err))
		return err
	}
	rpcServer.logger.Info().Msg(fmt.Sprintf("gRPC listening on %v", rpcServer.Listener.Addr()))

	// Starting REST proxy
	stopProxy, err := startRestProxy(
		server.cfg, rpcServer, restDialOpts, restListen, unlockerService,
	)
	if err != nil {
		return err
	}
	defer stopProxy()

	// Wait for password
	server.logger.Info().Msg("Waiting for password. Use `swarmcli setpassword` to set a password for the first time, " +
		"`swarmcli unlock` to unlock the daemon with an existing password, or `swarmcli changepassword` to change the " +
		"existing password and unlock the daemon.",
	)
	_, err = waitForPassword(unlockerService, interceptor.ShutdownChannel())
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Error while awaiting password: %v", err))
	}
	unlockerService.MacRespChan <- []byte("test")

	// Listen for shutdown signals
	<-interceptor.ShutdownChannel()
	return nil
}
...
// startRestProxy starts the given REST proxy on the listeners found in the config.
func startRestProxy(
	cfg *Config,
	rpcServer *RpcServer,
	restDialOpts []grpc.DialOption,
	restListen func(net.Addr) (net.Listener, error),
	unlockerService *unlocker.UnlockerService,
) (func(), error) {
	...
	err = rpcServer.RegisterWithRestProxy(
		ctx, mux, restDialOpts, restProxyDest,
	)
	if err != nil {
		return nil, err
	}
	err = unlockerService.RegisterWithRestProxy(
		ctx, mux, restDialOpts, restProxyDest,
	)
	if err != nil {
		return nil, err
	}
	...
}
...
// waitForPassword hangs until a password or an error are provided
func waitForPassword(u *unlocker.UnlockerService, shutdownChan <-chan struct{}) ([]byte, error) {
	select {
	case msg := <-u.PassChan:
		if msg.Err != nil {
			return nil, msg.Err
		}
		return msg.Password, nil
	case <-shutdownChan:
		return nil, fmt.Errorf("Shutting Down")
	}
}
```
At this point, we could build and test the login function with our Python script or with `curl`.
```
import protos.swarm_pb2 as swarm
import protos.swarm_pb2_grpc as swarmrpc
import protos.unlocker_pb2 as unlocker
import protos.unlocker_pb2_grpc as unlockerrpc
import grpc
import os

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

cert = open(os.path.expanduser('~/Library/Application Support/Bitswarmd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:4567', creds)
# channel = grpc.insecure_channel('localhost:4567')
stub = unlockerrpc.UnlockerStub(channel)
pwd="<redacted>"
response = stub.UnlockDaemon(unlocker.UnlockRequest(
    password=bytes(pwd, 'utf-8')
))
print(response)
```
We will now implement the `unlock`, `setpassword` and `changepassword` commands in our CLI as this will be the most common ways our node will be unlocked. You can add the commands to the `commands.go` file in `cmd/swarmcli` but I want to keep the commands for different services separated so I'm going to create a new file called `commands_unlocker.go`.
```
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
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/urfave/cli"
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	"gitlab.com/cypher-engineers/bitswarmd/utils"
	"golang.org/x/term"
)

var (
	statelessInitFlag = cli.BoolFlag{
		Name: "stateless_init",
		Usage: "do not create any macaroon files in the file " +
			"system of the daemon",
	}
	saveToFlag = cli.StringFlag{
		Name:  "save_to",
		Usage: "save returned admin macaroon to this file",
	}
)

var setPassword = cli.Command{
	Name:  "setpassword",
	Usage: "Sets a password when starting bitswarmd for the first time.",
	Description: `
	Sets a password used to unlock the macaroon key-store when starting bitswarmd for the first time.
	There is one required argument for this command, the password. There are optional flags for stateless_init
	and save_to for saving the returned macaroon to a specified file.`,
	Flags: []cli.Flag{
		statelessInitFlag,
		saveToFlag,
	},
	Action: setPwd,
}

// setPwd is the proxy command between swarmcli and gRPC equivalent.
func setPwd(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUnlockerClient(ctx) //This command returns the proto generated UnlockerClient instance
	defer cleanUp()
	statelessInit := ctx.Bool(statelessInitFlag.Name)
	if !statelessInit && ctx.IsSet(saveToFlag.Name) {
		return fmt.Errorf("Cannot set save_to flag without stateless_init")
	}
	pwd, err := capturePassword(
		"Input new password: ",
	)
	if err != nil {
		return err
	}
	resp, err := client.SetPassword(ctxc, &swarmrpc.SetPwdRequest{
		Password:      pwd,
		StatelessInit: statelessInit,
	})
	if err != nil {
		return err
	}
	fmt.Println("\nDaemon unlocked successfully!")
	if statelessInit {
		return storeOrPrintAdminMac(ctx, resp.AdminMacaroon)
	}
	return nil
}

var unlockCommand = cli.Command{
	Name:  "unlock",
	Usage: "Prompts the user to enter the previously set password to unlock the daemon.",
	Description: `
	Prompts the user to enter a password used to unlock the macaroon key-store when starting bitswarmd.
	There is one required argument for this command, the password.`,
	Action: unlock,
}

// unlock is the proxy command between swarmcli and gRPC equivalent.
func unlock(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUnlockerClient(ctx) //This command returns the proto generated UnlockerClient instance
	defer cleanUp()
	pwd, err := readPassword("Input password: ")
	if err != nil {
		return err
	}
	_, err = client.UnlockDaemon(ctxc, &swarmrpc.UnlockRequest{Password: pwd})
	if err != nil {
		return err
	}
	fmt.Println("\nDaemon unlocked successfully!")
	return nil
}

var changePassword = cli.Command{
	Name:  "changepassword",
	Usage: "Changes the previously set password.",
	Description: `
	Changes the previously set password used to unlock the macaroon key-store.
	There are two required arguments for this command, the old password and the new password. There are optional flags for stateless_init
	and save_to for saving the returned macaroon to a specified file.`,
	Flags: []cli.Flag{
		statelessInitFlag,
		saveToFlag,
	},
	Action: changePwd,
}

// changePwd is the proxy command between swarmcli and gRPC equivalent.
func changePwd(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUnlockerClient(ctx) //This command returns the proto generated UnlockerClient instance
	defer cleanUp()
	statelessInit := ctx.Bool(statelessInitFlag.Name)
	if !statelessInit && ctx.IsSet(saveToFlag.Name) {
		return fmt.Errorf("Cannot set save_to flag without stateless_init")
	}
	oldPwd, err := readPassword(
		"Input old password: ",
	)
	if err != nil {
		return err
	}
	newPwd, err := capturePassword(
		"Input new password: ",
	)
	resp, err := client.ChangePassword(ctxc, &swarmrpc.ChangePwdRequest{
		CurrentPassword: oldPwd,
		NewPassword:     newPwd,
		StatelessInit:   statelessInit,
	})
	if err != nil {
		return err
	}
	fmt.Println("\nDaemon unlocked successfully!")
	if statelessInit {
		return storeOrPrintAdminMac(ctx, resp.AdminMacaroon)
	}
	return nil
}

// storeOrPrintAdminMac stores the macaroon at the specified file if the save_to flag is provided or prints it to the console
func storeOrPrintAdminMac(ctx *cli.Context, adminMac []byte) error {
	if ctx.IsSet("save_to") {
		macSavePath := ctx.String("save_to")
		if !utils.FileExists(macSavePath) {
			_, err := os.Create(macSavePath)
			if err != nil {
				_ = os.Remove(macSavePath)
				return err
			}
		}
		err := ioutil.WriteFile(macSavePath, adminMac, 0644)
		if err != nil {
			_ = os.Remove(macSavePath)
			return err
		}
		fmt.Printf("Admin macaroon saved to %s\n", macSavePath)
		return nil
	}

	// Otherwise we just print it. The user MUST store this macaroon
	// somewhere so we either save it to a provided file path or just print
	// it to standard output.
	fmt.Printf("Admin macaroon: %s\n", hex.EncodeToString(adminMac))
	return nil
}

// capturePassword captures the password from the terminal and a confirmation of the password
func capturePassword(instruction string) ([]byte, error) {
	for {
		password, err := readPassword(instruction)
		if err != nil {
			return nil, err
		}
		pwdConfirmed, err := readPassword("Confirm new password: ")
		if bytes.Equal(password, pwdConfirmed) {
			return password, nil
		}
		fmt.Println("Passwords don't match, please try again")
		fmt.Println()
	}
}

// readPassword reads a password from the terminal.
func readPassword(instruction string) ([]byte, error) {
	fmt.Print(instruction)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	if len(pw) == 0 {
		return nil, fmt.Errorf("Password cannot be blank")
	}
	fmt.Println()
	return pw, err
}
```
Now we need to create `getUnlockerClient()` in our `cmd/swarmcli/main.go` and add the commands to the App itself.
```
// getUnlockerClient returns the UnlockerClient instance from the swarmrpc package as well as a cleanup function
func getUnlockerClient(ctx *cli.Context) (swarmrpc.UnlockerClient, func()) {
	args := extractArgs(ctx)
	conn, err := auth.GetClientConn(args.RPCAddr, args.RPCPort, args.TLSCertPath)
	if err != nil {
		fatal(err)
	}
	cleanUp := func() {
		conn.Close()
	}
	return swarmrpc.NewUnlockerClient(conn), cleanUp
}
...
// main is the entrypoint for swarmcli
func main() {
	app := cli.NewApp()
	app.Name = "swarmcli"
	app.Usage = "Command Line tool for the Bitswarm Daemon (bitswarmd)"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "rpc_addr",
			Value: defaultRPCAddr,
			Usage: "The host address of the Bitswarm daemon (exclude the port)",
		},
		cli.StringFlag{
			Name:  "rpc_port",
			Value: defaultRPCPort,
			Usage: "The host port of the Bitswarm daemon",
		},
		cli.StringFlag{
			Name:      "tlscertpath",
			Value:     defaultTLSCertPath,
			Usage:     "The path to bitswarmd's TLS certificate.",
			TakesFile: true,
		},
	}
	app.Commands = []cli.Command{
		stopCommand,
		testCommand,
		setPassword,
		unlockCommand,
		changePassword,
	}
	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
```
Now we can test with `swarmcli`. Try different scenarios, give a blank password, try using `UnlockerService` commands after unlocking, `Swarm` commands before unlocking or using the `stateless_init` and `save_to` flags. Note that for `save_to` absolute paths should be used as inputting characters like `~` yields errors. 

## Step 16: Macaroon Store and Service

We have a password stored in our kvdb now and we can proceed with creating the `macaroons` package. This was the hardest part of deconstructing LND as it required reading up on the `macaroon` and `btcsuite/btcwallet` package documentation. I removed the IP lock constraint for the macaroon but feel free to include it in your project if you wish. First is `store.go`
```
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
package macaroons

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/btcsuite/btcwallet/snacl"
	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
	bolt "go.etcd.io/bbolt"
)

var (
	rootKeyBucketName        = []byte("macrootkeys")
	RootKeyIDContextKey      = contextKey{"rootkeyid"}
	RootKeyLen               = 32
	DefaultRootKeyID         = []byte("0")
	encryptionKeyID          = []byte("enckey")
	ErrAlreadyUnlocked       = fmt.Errorf("macaroon store already unlocked")
	ErrContextRootKeyID      = fmt.Errorf("failed to read root key ID from context")
	ErrKeyValueForbidden     = fmt.Errorf("root key ID value is not allowed")
	ErrPasswordRequired      = fmt.Errorf("a non-nil password is required")
	ErrStoreLocked           = fmt.Errorf("macaroon store is locked")
	ErrRootKeyBucketNotFound = fmt.Errorf("Root key bucket not found")
	ErrEncKeyNotFound        = fmt.Errorf("macaroon encryption key not found")
	ErrDeletionForbidden     = fmt.Errorf("the specified ID cannot be deleted")
)

type contextKey struct {
	Name string
}

type RootKeyStorage struct {
	kvdb.DB
	encKey *snacl.SecretKey // Don't roll your own crypto
}

// InitRootKeyStorage initializes the top level bucket within the bbolt db for macaroons
func InitRootKeyStorage(db kvdb.DB) (*RootKeyStorage, error) {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(rootKeyBucketName)
		return err
	}); err != nil {
		return nil, err
	}
	return &RootKeyStorage{
		DB:     db,
		encKey: nil,
	}, nil
}

// Get returns the root key for the given id. If the item is not there, it returns an error
func (r *RootKeyStorage) Get(_ context.Context, id []byte) ([]byte, error) {
	r.Mutex.RLock()
	defer r.Mutex.RUnlock()
	if r.encKey == nil {
		return nil, ErrStoreLocked
	}
	var rootKey []byte
	err := r.DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName) // get the rootkey bucket
		if bucket == nil {
			return ErrRootKeyBucketNotFound
		}
		dbKey := bucket.Get(id) //get the encryption key kv pair
		if len(dbKey) == 0 {
			return fmt.Errorf("Root key with id %s doesn't exist", string(id))
		}
		decKey, err := r.encKey.Decrypt(dbKey)
		if err != nil {
			return err
		}
		rootKey = make([]byte, len(decKey))
		copy(rootKey[:], decKey)
		return nil
	})
	if err != nil {
		rootKey = nil
		return nil, err
	}
	return rootKey, nil
}

// RootKeyIDFromContext retrieves the root key ID from context using the key
// RootKeyIDContextKey.
func RootKeyIDFromContext(ctx context.Context) ([]byte, error) {
	id, ok := ctx.Value(RootKeyIDContextKey).([]byte)
	if !ok {
		return nil, ErrContextRootKeyID
	}
	if len(id) == 0 {
		return nil, ErrMissingRootKeyID
	}
	return id, nil
}

// generateAndStoreNewRootKey creates a new random RootKeyLen-byte root key,
// encrypts it with the given encryption key and stores it in the bucket.
// Any previously set key will be overwritten.
func generateAndStoreNewRootKey(bucket *bolt.Bucket, id []byte,
	key *snacl.SecretKey) ([]byte, error) {

	rootKey := make([]byte, RootKeyLen)
	if _, err := io.ReadFull(rand.Reader, rootKey); err != nil {
		return nil, err
	}

	encryptedKey, err := key.Encrypt(rootKey)
	if err != nil {
		return nil, err
	}
	return rootKey, bucket.Put(id, encryptedKey)
}

// Implements RootKey from the bakery.RootKeyStorage interface
func (r *RootKeyStorage) RootKey(ctx context.Context) ([]byte, []byte, error) {
	r.Mutex.RLock()
	defer r.Mutex.RUnlock()
	if r.encKey == nil {
		return nil, nil, ErrStoreLocked
	}
	id, err := RootKeyIDFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(id, encryptionKeyID) {
		return nil, nil, ErrKeyValueForbidden
	}
	var rootKey []byte
	err = r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName) // get the rootkey bucket
		if bucket == nil {
			return fmt.Errorf("Root key bucket not found")
		}
		dbKey := bucket.Get(id) //get the encryption key kv pair
		if len(dbKey) != 0 {
			decKey, err := r.encKey.Decrypt(dbKey)
			if err != nil {
				return err
			}

			rootKey = make([]byte, len(decKey))
			copy(rootKey[:], decKey[:])
			return nil
		}
		newKey, err := generateAndStoreNewRootKey(bucket, id, r.encKey)
		rootKey = newKey
		return err
	})
	if err != nil {
		rootKey = nil
		return nil, nil, err
	}
	return rootKey, id, err
}

// CreateUnlock sets an encryption key if one isn't already set or checks if the password is correct for the existing encryption key.
func (r *RootKeyStorage) CreateUnlock(password *[]byte) error {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if r.encKey != nil {
		return ErrAlreadyUnlocked
	}
	if password == nil {
		return ErrPasswordRequired
	}
	return r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName) // get the rootkey bucket
		if bucket == nil {
			return fmt.Errorf("Root key bucket not found")
		}
		dbKey := bucket.Get(encryptionKeyID) //get the encryption key kv pair
		if len(dbKey) > 0 {
			// dbKey has already been set
			encKey := &snacl.SecretKey{}
			err := encKey.Unmarshal(dbKey)
			if err != nil {
				return err
			}
			err = encKey.DeriveKey(password)
			if err != nil {
				return err
			}
			r.encKey = encKey
			return nil
		}
		// no key has been set so creating a new one
		encKey, err := snacl.NewSecretKey(
			password, snacl.DefaultN, snacl.DefaultR, snacl.DefaultP,
		)
		if err != nil {
			return err
		}
		err = bucket.Put(encryptionKeyID, encKey.Marshal())
		if err != nil {
			return err
		}
		r.encKey = encKey
		return nil
	})
}

// Close resets the encryption key in memory
func (r *RootKeyStorage) Close() error {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if r.encKey != nil {
		r.encKey.Zero()
		r.encKey = nil
	}
	return nil
}

// ChangePassword decrypts the macaroon root key with the old password and then
// encrypts it again with the new password.
func (r *RootKeyStorage) ChangePassword(oldPw, newPw []byte) error {
	// We need the store to already be unlocked. With this we can make sure
	// that there already is a key in the DB.
	if r.encKey == nil {
		return ErrStoreLocked
	}

	// Check if a nil password has been passed; return an error if so.
	if oldPw == nil || newPw == nil {
		return ErrPasswordRequired
	}

	return r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName)
		if bucket == nil {
			return ErrRootKeyBucketNotFound
		}
		encKeyDb := bucket.Get(encryptionKeyID)
		rootKeyDb := bucket.Get(DefaultRootKeyID)

		// Both the encryption key and the root key must be present
		// otherwise we are in the wrong state to change the password.
		if len(encKeyDb) == 0 || len(rootKeyDb) == 0 {
			return ErrEncKeyNotFound
		}

		// Unmarshal parameters for old encryption key and derive the
		// old key with them.
		encKeyOld := &snacl.SecretKey{}
		err := encKeyOld.Unmarshal(encKeyDb)
		if err != nil {
			return err
		}
		err = encKeyOld.DeriveKey(&oldPw)
		if err != nil {
			return err
		}

		// Create a new encryption key from the new password.
		encKeyNew, err := snacl.NewSecretKey(
			&newPw, snacl.DefaultN, snacl.DefaultR, snacl.DefaultP,
		)
		if err != nil {
			return err
		}

		// Now try to decrypt the root key with the old encryption key,
		// encrypt it with the new one and then store it in the DB.
		decryptedKey, err := encKeyOld.Decrypt(rootKeyDb)
		if err != nil {
			return err
		}
		rootKey := make([]byte, len(decryptedKey))
		copy(rootKey, decryptedKey)
		encryptedKey, err := encKeyNew.Encrypt(rootKey)
		if err != nil {
			return err
		}
		err = bucket.Put(DefaultRootKeyID, encryptedKey)
		if err != nil {
			return err
		}

		// Finally, store the new encryption key parameters in the DB
		// as well.
		err = bucket.Put(encryptionKeyID, encKeyNew.Marshal())
		if err != nil {
			return err
		}

		r.encKey = encKeyNew
		return nil
	})
}

// GenerateNewRootKey generates a new macaroon root key, replacing the previous
// root key if it existed.
func (r *RootKeyStorage) GenerateNewRootKey() error {
	// We need the store to already be unlocked. With this we can make sure
	// that there already is a key in the DB that can be replaced.
	if r.encKey == nil {
		return ErrStoreLocked
	}
	return r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName)
		if bucket == nil {
			return ErrRootKeyBucketNotFound
		}
		_, err := generateAndStoreNewRootKey(
			bucket, DefaultRootKeyID, r.encKey,
		)
		return err
	})
}

// ListMacaroonIDs returns all the root key ID values except the value of
// encryptedKeyID.
func (r *RootKeyStorage) ListMacaroonIDs(_ context.Context) ([][]byte, error) {
	r.Mutex.RLock()
	defer r.Mutex.RUnlock()

	// Check it's unlocked.
	if r.encKey == nil {
		return nil, ErrStoreLocked
	}

	var rootKeySlice [][]byte

	// Read all the items in the bucket and append the keys, which are the
	// root key IDs we want.
	err := r.DB.View(func(tx *bolt.Tx) error {
		// As this is meant to be a read-only operation, rollback any unintended changes
		defer func() {
			rootKeySlice = nil
			tx.Rollback()
		}()
		// appendRootKey is a function closure that appends root key ID
		// to rootKeySlice.
		appendRootKey := func(k, _ []byte) error {
			// Only append when the key value is not encryptedKeyID.
			if !bytes.Equal(k, encryptionKeyID) {
				rootKeySlice = append(rootKeySlice, k)
			}
			return nil
		}

		return tx.Bucket(rootKeyBucketName).ForEach(appendRootKey)
	})
	if err != nil {
		return nil, err
	}

	return rootKeySlice, nil
}

// DeleteMacaroonID removes one specific root key ID. If the root key ID is
// found and deleted, it will be returned.
func (r *RootKeyStorage) DeleteMacaroonID(
	_ context.Context, rootKeyID []byte) ([]byte, error) {

	r.Mutex.RLock()
	defer r.Mutex.RUnlock()

	// Check it's unlocked.
	if r.encKey == nil {
		return nil, ErrStoreLocked
	}

	// Check the rootKeyID is not empty.
	if len(rootKeyID) == 0 {
		return nil, ErrMissingRootKeyID
	}

	// Deleting encryptedKeyID or DefaultRootKeyID is not allowed.
	if bytes.Equal(rootKeyID, encryptionKeyID) ||
		bytes.Equal(rootKeyID, DefaultRootKeyID) {

		return nil, ErrDeletionForbidden
	}

	var rootKeyIDDeleted []byte
	err := r.DB.Update(func(tx *bolt.Tx) error {
		// As this is meant to be a read-only operation, rollback any unintended changes
		defer func() {
			rootKeyIDDeleted = nil
		}()
		bucket := tx.Bucket(rootKeyBucketName)

		// Check the key can be found. If not, return nil.
		if bucket.Get(rootKeyID) == nil {
			return nil
		}

		// Once the key is found, we do the deletion.
		if err := bucket.Delete(rootKeyID); err != nil {
			return err
		}
		rootKeyIDDeleted = rootKeyID

		return nil
	})
	if err != nil {
		return nil, err
	}

	return rootKeyIDDeleted, nil
}
```
I had to do some modifications to what's in LND since we are using our own `kvdb` struct and not theirs. For all cryptography related stuff, I used the `btcsuite/btcwallet/snacl` package. "Don't roll your own crypto", the old adage goes. And so I followed it. Then we build our macaroon service `service.go`.
```
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
package macaroons

import (
	"context"
	"encoding/hex"
	"fmt"

	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
	"google.golang.org/grpc/metadata"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2"
)

var (
	PermissionEntityCustomURI = "uri"
	ErrMissingRootKeyID       = fmt.Errorf("Missing root key ID")
)

type MacaroonValidator interface {
	ValidateMacaroon(ctx context.Context, requiredPermissions []bakery.Op, fullMethod string) error
}

type Service struct {
	bakery.Bakery

	rks                *RootKeyStorage
	ExternalValidators map[string]MacaroonValidator
	StatelessInit      bool
}

// InitService returns initializes the rootkeystorage for the Macaroon service and returns the initialized service
func InitService(db kvdb.DB, location string, statelessInit bool, checks ...Checker) (*Service, error) {
	rks, err := InitRootKeyStorage(db)
	if err != nil {
		return nil, err
	}
	bakeryParams := bakery.BakeryParams{
		Location:     location,
		RootKeyStore: rks,
		Locator:      nil,
		Key:          nil,
	}
	service := bakery.New(bakeryParams)
	return &Service{
		Bakery:             *service,
		rks:                rks,
		ExternalValidators: make(map[string]MacaroonValidator),
		StatelessInit:      statelessInit,
	}, nil
}

// isRegistered checks to see if the required checker has already been registered to avoid duplicates
func isRegistered(c *checkers.Checker, name string) bool {
	if c == nil {
		return false
	}
	for _, info := range c.Info() {
		if info.Name == name && info.Prefix == "" && info.Namespace == "std" {
			return true
		}
	}
	return false
}

// RegisterExternalValidator registers a custom, external macaroon validator for
// the specified absolute gRPC URI. That validator is then fully responsible to
// make sure any macaroon passed for a request to that URI is valid and
// satisfies all conditions.
func (svc *Service) RegisterExternalValidator(fullMethod string,
	validator MacaroonValidator) error {

	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}

	_, ok := svc.ExternalValidators[fullMethod]
	if ok {
		return fmt.Errorf("external validator for method %s already "+
			"registered", fullMethod)
	}

	svc.ExternalValidators[fullMethod] = validator
	return nil
}

// ValidateMacaroon validates the capabilities of a given request given a
// bakery service, context, and uri. Within the passed context.Context, we
// expect a macaroon to be encoded as request metadata using the key
// "macaroon".
func (svc *Service) ValidateMacaroon(ctx context.Context,
	requiredPermissions []bakery.Op, fullMethod string) error {

	// Get macaroon bytes from context and unmarshal into macaroon.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("unable to get metadata from context")
	}
	if len(md["macaroon"]) != 1 {
		return fmt.Errorf("expected 1 macaroon, got %d",
			len(md["macaroon"]))
	}

	// With the macaroon obtained, we'll now decode the hex-string
	// encoding, then unmarshal it from binary into its concrete struct
	// representation.
	macBytes, err := hex.DecodeString(md["macaroon"][0])
	if err != nil {
		return err
	}
	mac := &macaroon.Macaroon{}
	err = mac.UnmarshalBinary(macBytes)
	if err != nil {
		return err
	}

	// Check the method being called against the permitted operation, the
	// expiration time and IP address and return the result.
	authChecker := svc.Checker.Auth(macaroon.Slice{mac})
	_, err = authChecker.Allow(ctx, requiredPermissions...)

	// If the macaroon contains broad permissions and checks out, we're
	// done.
	if err == nil {
		return nil
	}

	// To also allow the special permission of "uri:<FullMethod>" to be a
	// valid permission, we need to check it manually in case there is no
	// broader scope permission defined.
	_, err = authChecker.Allow(ctx, bakery.Op{
		Entity: PermissionEntityCustomURI,
		Action: fullMethod,
	})
	return err
}

// Close closes the rootkeystorage of the macaroon service
func (s *Service) Close() error {
	return s.rks.Close()
}

// Thin-wrapper for the CreateUnlock function of the RootKeyStorage attribute of the Service
func (s *Service) CreateUnlock(password *[]byte) error {
	return s.rks.CreateUnlock(password)
}

// ContextWithRootKeyId passes the root key ID value to context
func ContextWithRootKeyId(ctx context.Context, value interface{}) context.Context {
	return context.WithValue(ctx, RootKeyIDContextKey, value)
}

// NewMacaroon is a wrapper around the Oven.NewMacaroon method and returns a freshly baked macaroon
func (s *Service) NewMacaroon(ctx context.Context, rootKeyId []byte, noCaveats bool, cav []checkers.Caveat, ops ...bakery.Op) (*bakery.Macaroon, error) {
	if len(rootKeyId) == 0 {
		return nil, ErrMissingRootKeyID
	}
	ctx = ContextWithRootKeyId(ctx, rootKeyId)
	if !noCaveats {
		return s.Oven.NewMacaroon(ctx, bakery.LatestVersion, nil, ops...)
	}
	return s.Oven.NewMacaroon(ctx, bakery.LatestVersion, cav, ops...)
}

// ChangePassword calls the underlying root key store's ChangePassword and returns the result.
func (svc *Service) ChangePassword(oldPw, newPw []byte) error {
	return svc.rks.ChangePassword(oldPw, newPw)
}
```
And then lastly we have the `constraints.go` and `auth.go` files.
`constraints.go`
```
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
package macaroons

import (
	"time"

	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2"
)

type Constraint func(*macaroon.Macaroon) error

type Checker func() (string, checkers.Func)

// AddConstraints returns new derived macaroon by applying every passed
// constraint and tightening its restrictions.
func AddConstraints(mac *macaroon.Macaroon, cs ...Constraint) (*macaroon.Macaroon, error) {
	newMac := mac.Clone()
	for _, constraint := range cs {
		if err := constraint(newMac); err != nil {
			return nil, err
		}
	}
	return newMac, nil
}

// Each *Constraint function is a functional option, which takes a pointer
// to the macaroon and adds another restriction to it. For each *Constraint,
// the corresponding *Checker is provided if not provided by default.

// TimeoutConstraint restricts the lifetime of the macaroon
// to the amount of seconds given.
func TimeoutConstraint(seconds int64) func(*macaroon.Macaroon) error {
	return func(mac *macaroon.Macaroon) error {
		caveat := TimeoutCaveat(seconds)
		return mac.AddFirstPartyCaveat([]byte(caveat.Condition))
	}
}

// TimeoutCaveat is a wrapper function which returns a checkers.Caveat struct
func TimeoutCaveat(seconds int64) checkers.Caveat {
	macaroonTimeout := time.Duration(seconds)
	requestTimeout := time.Now().Add(time.Second * macaroonTimeout)
	return checkers.TimeBeforeCaveat(requestTimeout)
}
```
`auth.go`
```
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
package macaroons

import (
	"context"
	"encoding/hex"

	macaroon "gopkg.in/macaroon.v2"
)

type MacaroonCredential struct {
	*macaroon.Macaroon
}

// RequireTransportSecurity implements the PerRPCCredentials interface.
func (m MacaroonCredential) RequireTransportSecurity() bool {
	return true
}

// GetRequestMetadata implements the PerRPCCredentials interface. This method
// is required in order to pass the wrapped macaroon into the gRPC context.
// With this, the macaroon will be available within the request handling scope
// of the ultimate gRPC server implementation.
func (m MacaroonCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {

	macBytes, err := m.MarshalBinary()
	if err != nil {
		return nil, err
	}

	md := make(map[string]string)
	md["macaroon"] = hex.EncodeToString(macBytes)
	return md, nil
}

// NewMacaroonCredential returns a copy of the passed macaroon wrapped in a
// MacaroonCredential struct which implements PerRPCCredentials.
func NewMacaroonCredential(m *macaroon.Macaroon) MacaroonCredential {
	ms := MacaroonCredential{}
	ms.Macaroon = m.Clone()
	return ms
}
```
I would encourage anyone attempting this to try and cut out the code from the LND package itself instead of copying what I've created. It helps you understand what's actually going on with macaroons. I'd give more of an explanation but my brain is pretty fried at this point from having done it myself.

## Step 17: Macaroon gRPC Middleware

Now that we have a `macaroons` package, we need to add macaroon verification to our gRPC middleware. We will also be whitelisting our `UnlockerService` commands since on initial startup, we won't have any macaroons to give the daemon.

```
var (
	...
	// List of commands that don't need macaroons
	macaroonWhitelist = map[string]struct{}{
		"/swarmrpc.Unlocker/SetPassword":    {},
		"/swarmrpc.Unlocker/UnlockDaemon":   {},
		"/swarmrpc.Unlocker/ChangePassword": {},
	}
)

// GrpcInteceptor struct is a data structure with attributes relevant to creating the gRPC interceptor
type GrpcInterceptor struct {
	state         rpcState
	noMacaroons   bool
	log           *zerolog.Logger
	permissionMap map[string][]bakery.Op
	svc           *macaroons.Service
	sync.RWMutex
}

// NewGrpcInterceptor instantiates a new GrpcInterceptor struct
func NewGrpcInterceptor(log *zerolog.Logger, noMacaroons bool) *GrpcInterceptor {
	return &GrpcInterceptor{
		state:         daemonLocked,
		noMacaroons:   noMacaroons,
		log:           log,
		permissionMap: make(map[string][]bakery.Op),
	}
}
...
// CreateGrpcOptions creates a array of gRPC interceptors
func (i *GrpcInterceptor) CreateGrpcOptions() []grpc.ServerOption {
	...
	// add macaroon interceptors
	unaryInterceptors = append(
		unaryInterceptors, i.MacaroonUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, i.MacaroonStreamServerInterceptor(),
	)
	// Create server options from the interceptors we just set up.
	chainedUnary := grpc_middleware.WithUnaryServerChain(
		unaryInterceptors...,
	)
	chainedStream := grpc_middleware.WithStreamServerChain(
		strmInterceptors...,
	)
	serverOpts := []grpc.ServerOption{chainedUnary, chainedStream}
	return serverOpts
}
...
// AddPermissions adds the inputted permission to the permissionMap attribute of the GrpcInterceptor struct
func (i *GrpcInterceptor) AddPermissions(perms map[string][]bakery.Op) error {
	for m, ops := range perms {
		err := i.AddPermission(m, ops)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddPermission adds a new macaroon rule for the given method
func (i *GrpcInterceptor) AddPermission(method string, ops []bakery.Op) error {
	if _, ok := i.permissionMap[method]; ok {
		return fmt.Errorf("Detected duplicate macaroon constraints for path: %v", method)
	}
	i.permissionMap[method] = ops
	return nil
}

// Permissions returns the current set of macaroon permissions
func (i *GrpcInterceptor) Permissions() map[string][]bakery.Op {
	c := make(map[string][]bakery.Op)
	for k, v := range i.permissionMap {
		s := make([]bakery.Op, len(v))
		copy(s, v)
		c[k] = s
	}
	return c
}

// checkMacaroon validates that the context contains the macaroon needed to
// invoke the given RPC method.
func (i *GrpcInterceptor) checkMacaroon(ctx context.Context,
	fullMethod string) error {

	// If noMacaroons is set, we'll always allow the call.
	if i.noMacaroons {
		return nil
	}

	// Check whether the method is whitelisted, if so we'll allow it
	// regardless of macaroons.
	_, ok := macaroonWhitelist[fullMethod]
	if ok {
		return nil
	}
	svc := i.svc

	// If the macaroon service is not yet active, we cannot allow
	// the call.
	if svc == nil {
		return fmt.Errorf("Unable to determine macaroon permissions")
	}

	uriPermissions, ok := i.permissionMap[fullMethod]
	if !ok {
		return fmt.Errorf("%s: unknown permissions required for method",
			fullMethod)
	}

	// Find out if there is an external validator registered for
	// this method. Fall back to the internal one if there isn't.
	validator, ok := svc.ExternalValidators[fullMethod]
	if !ok {
		validator = svc
	}

	// Now that we know what validator to use, let it do its work.
	return validator.ValidateMacaroon(ctx, uriPermissions, fullMethod)
}

// MacaroonUnaryServerInterceptor is a GRPC interceptor that checks whether the
// request is authorized by the included macaroons.
func (i *GrpcInterceptor) MacaroonUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
		// Check macaroons.
		if err := i.checkMacaroon(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// MacaroonStreamServerInterceptor is a GRPC interceptor that checks whether
// the request is authorized by the included macaroons.
func (i *GrpcInterceptor) MacaroonStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Check macaroons.
		err := i.checkMacaroon(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// Adds the macaroon service provided to GrpcInterceptor struct attributes
func (i *GrpcInterceptor) AddMacaroonService(service *macaroons.Service) {
	i.svc = service
}
```

## Step 18: Macaroon Integration

We need to register our macaroon `Service` with the gRPC middleware so that it can hand any macaroons to the `Service` for validation. 

We will define a set of permissions for all our gRPC commands in `rpcserver.go`
```
var (
	readPermissions = []bakery.Op{
		{
			Entity: "swarm",
			Action: "read",
		},
		{
			Entity: "macaroon",
			Action: "read",
		},
	}
	writePermissions = []bakery.Op{
		{
			Entity: "swarm",
			Action: "write",
		},
		{
			Entity: "macaroon",
			Action: "write",
		},
		{
			Entity: "macaroon",
			Action: "generate",
		},
	}
	validActions  = []string{"read", "write", "generate"}
	validEntities = []string{
		"swarm", "macaroon",
		macaroons.PermissionEntityCustomURI,
	}
)

// MainRPCServerPermissions returns a mapping of the main RPC server calls to
// the permissions they require.
func MainRPCServerPermissions() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		"/swarmrpc.Swarm/StopDaemon": {{
			Entity: "swarm",
			Action: "write",
		}},
		"/swarmrpc.Swarm/TestCommand": {{
			Entity: "swarm",
			Action: "read",
		}},
	}
}
```
We don't define any permissions for the `UnlockerService` commands since they don't require authentication. Next we will add `AdminMacPath` and `TestMacPath` `Config` parameters in `config.go`
```
type Config struct {
	DefaultLogDir  bool     `yaml:"DefaultLogDir"`
	LogFileDir     string   `yaml:"LogFileDir"`
	ConsoleOutput  bool     `yaml:"ConsoleOutput"`
	GrpcPort       int64    `yaml:"GrpcPort"`
	RestPort       int64    `yaml:"RestPort"`
	ExtraIPAddr    []string `yaml:"ExtraIPAddr"` // optional parameter
	TLSCertPath    string
	TLSKeyPath     string
	MacaroonDBPath string
	AdminMacPath   string
	TestMacPath    string
	WSPingInterval time.Duration
	WSPongWait     time.Duration
}

// all default values will be defined here
var (
	...
	default_admin_macaroon_path string = default_log_dir() + "/admin.macaroon"
	test_macaroon_path          string = default_log_dir() + "/test.macaroon"
	default_config                     = func() Config {
		return Config{
			DefaultLogDir:  true,
			LogFileDir:     default_log_dir(),
			ConsoleOutput:  true,
			GrpcPort:       default_grpc_port,
			RestPort:       default_rest_port,
			TLSCertPath:    default_tls_cert_path,
			TLSKeyPath:     default_tls_key_path,
			MacaroonDBPath: default_macaroon_db_file,
			AdminMacPath:   default_admin_macaroon_path,
			TestMacPath:    test_macaroon_path,
			WSPingInterval: default_ws_ping_interval,
			WSPongWait:     default_ws_pong_wait,
		}
	}
)
...
// check_yaml_config assigns default values to any empty attributes that were not defined in the yaml file
func check_yaml_config(config Config) Config {
	pv := reflect.ValueOf(&config)
	v := pv.Elem()
	field_names := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		field_name := field_names.Field(i).Name
		switch field_name {
		...
		case "AdminMacPath":
			if f.String() == "" {
				change_field(f, default_admin_macaroon_path)
			}
		case "TestMacPath":
			if f.String() == "" {
				change_field(f, test_macaroon_path)
			}
		}
	}
	return config
}
```
We now initialize our macaroon `Service`, take the password that is returned by `waitForPassword()`, add our permissions to the gRPC middleware, unlock the macaroon key-store and bake some macaroons!
`server.go`
```
func Main() {
	...
	// Creating gRPC server and Server options
	grpc_interceptor := intercept.NewGrpcInterceptor(rpcServer.logger, false)
	err = grpc_interceptor.AddPermissions(MainRPCServerPermissions())
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not add RPC server permissions to gRPC middleware: %v", err))
		return err
	}
	rpcServerOpts := grpc_interceptor.CreateGrpcOptions()
	serverOpts = append(serverOpts, rpcServerOpts...)
	grpc_server := grpc.NewServer(serverOpts...)
	rpcServer.RegisterWithGrpcServer(grpc_server)
	...
	// Instantiate Unlocker Service and register with gRPC server
	server.logger.Info().Msg("Initializing unlocker service...")
	unlockerService, err := unlocker.NewUnlockerService(db, []string{server.cfg.AdminMacPath, server.cfg.TestMacPath}) // new input arguments
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize unlocker service: %v", err))
		return err
	}
	defer unlockerService.Stop()
	unlockerService.RegisterWithGrpcServer(grpc_server)
	server.logger.Info().Msg("Unlocker service initialized.")
	...
	// Wait for password
	server.logger.Info().Msg("Waiting for password. Use `swarmcli setpassword` to set a password for the first time, " +
		"`swarmcli unlock` to unlock the daemon with an existing password, or `swarmcli changepassword` to change the " +
		"existing password and unlock the daemon.",
	)
	resp, err := waitForPassword(unlockerService, interceptor.ShutdownChannel())
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Error while awaiting password: %v", err))
	}

	// Instantiating Macaroon Service
	server.logger.Info().Msg("Initiating macaroon service...")
	macaroonService, err := macaroons.InitService(*db, "bitswarmd", resp.StatelessInit)
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Unable to instantiate Macaroon service: %v", err))
		return err
	}
	server.logger.Info().Msg("Macaroon service initialized.")
	defer macaroonService.Close()

	// Unlock Macaroon Store
	server.logger.Info().Msg("Unlocking macaroon store...")
	err = macaroonService.CreateUnlock(&resp.Password)
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Unable to unlock macaroon store: %v", err))
		return err
	}
	server.logger.Info().Msg("Macaroon store unlocked.")

	// Baking Macaroons
	server.logger.Info().Msg("Baking macaroons...")
	adminMac, err := bakeMacaroons(ctx, macaroonService, adminPermissions(), false, 0)
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Unable to create admin macaroon: %v", err))
		return err
	}
	unlockerService.MacRespChan <- adminMac
	if !macaroonService.StatelessInit &&
		!utils.FileExists(server.cfg.AdminMacPath) &&
		!utils.FileExists(server.cfg.TestMacPath) {
		err := genMacaroons(
			ctx, macaroonService, server.cfg.AdminMacPath, adminPermissions(), false, 0,
		)
		if err != nil {
			server.logger.Error().Msg(fmt.Sprintf("Unable to create admin macaroon: %v", err))
			return err
		}
		err = genMacaroons(
			ctx, macaroonService, server.cfg.TestMacPath, readPermissions, true, 120,
		)
		if err != nil {
			server.logger.Error().Msg(fmt.Sprintf("Unable to create test macaroon: %v", err))
			return err
		}
		server.logger.Info().Msg("Macaroons baked successfully.")
	}
	if macaroonService.StatelessInit {
		msg := "Found %s macaroon on disk (%s) even though " +
			"--stateless_init was requested. Unencrypted " +
			"state is accessible by the host system. You " +
			"should change the password and delete " +
			"old macaroons. Then restart and use --stateless_init."

		if utils.FileExists(server.cfg.AdminMacPath) {
			server.logger.Warn().Msg(fmt.Sprintf(msg, "admin"))
		}
		if utils.FileExists(server.cfg.TestMacPath) {
			server.logger.Warn().Msg(fmt.Sprintf(msg, "test"))
		}
	}
	grpc_interceptor.AddMacaroonService(macaroonService)

	// Change gRPC middleware state from daemonLocked to daemonUnlocked
	grpc_interceptor.SetDaemonUnlocked()
	...
}
...
// waitForPassword hangs until a password or an error are provided
func waitForPassword(u *unlocker.UnlockerService, shutdownChan <-chan struct{}) (*unlocker.PasswordMsg, error) {
	select {
	case msg := <-u.PassChan:
		if msg.Err != nil {
			return nil, msg.Err
		}
		return msg, nil
	case <-shutdownChan:
		return nil, fmt.Errorf("Shutting Down")
	}
}

// adminPermissions returns the permissions associated with the admin macaroon
func adminPermissions() []bakery.Op {
	admin := make([]bakery.Op, len(readPermissions)+len(writePermissions))
	copy(admin[:len(readPermissions)], readPermissions)
	copy(admin[len(readPermissions):], writePermissions)
	return admin
}

// bakeMacaroons is a wrapper function around the NewMacaroon method of the macaroons.Service struct
func bakeMacaroons(ctx context.Context, svc *macaroons.Service, perms []bakery.Op, noTimeOutCaveat bool, seconds int64) ([]byte, error) {
	mac, err := svc.NewMacaroon(
		ctx,
		macaroons.DefaultRootKeyID,
		noTimeOutCaveat,
		[]checkers.Caveat{macaroons.TimeoutCaveat(seconds)},
		perms...,
	)
	if err != nil {
		return nil, err
	}
	return mac.M().MarshalBinary()
}

// genMacaroons will create the macaroon files specified if not already created
func genMacaroons(ctx context.Context, svc *macaroons.Service, macFile string, perms []bakery.Op, noTimeOutCaveat bool, seconds int64) error {
	macBytes, err := bakeMacaroons(ctx, svc, perms, noTimeOutCaveat, seconds)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(macFile, macBytes, 0755)
	if err != nil {
		_ = os.Remove(macFile)
		return err
	}
	return nil
}
```
Okay there's alot going on here. First, we changed the input arguments to `NewUnlockerService()` to include an array of the paths for both our macaroons. This is because now when we change passwords, we need to also delete the old macaroons. I will highlight the changes to `ChangePassword()` below. The response from `waitForPassword()` is no longer the byte array of the password but is now the `*PasswordMsg` struct from the channel. This is because we want our macaroon `Service` to have a `StatelessInit` attribute. After we initialize and unlock the macaroon store, we then bake some macaroons only if they don't already exist and we aren't in `StatelessInit` mode. Regardless, we pass the bytes for the admin macaroon down the `MacRespChan` channel so that `UnlockerService` doesn't hang waiting for it. Finally, we also change the state of the gRPC middlware and set it to unlocked to prevent users from using `UnlockerService` commands after the daemon is unlocked. The final thing we need to do is include macaroons into our CLI. But first, I will show you the changes to `unlocker/service.go`
```
type UnlockerService struct {
	swarmrpc.UnimplementedUnlockerServer
	PassChan      chan *PasswordMsg
	MacRespChan   chan []byte
	macaroonDB    *kvdb.DB
	macaroonFiles []string
}

// NewUnlockerService creates a new instance of the UnlockerService needed for set passwords, unlocking the macaroon key-store and changing passwords
func NewUnlockerService(db *kvdb.DB, macaroonFiles []string) (*UnlockerService, error) {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(pwdKeyBucketName)
		return err
	}); err != nil {
		return nil, err
	}
	return &UnlockerService{
		PassChan:      make(chan *PasswordMsg, 1),
		MacRespChan:   make(chan []byte, 1),
		macaroonDB:    db,
		macaroonFiles: macaroonFiles,
	}, nil
}
...
// ChangePassword takes the old password, validates it and sets the new password from the inputted new password only if a previous password has been set
func (u *UnlockerService) ChangePassword(ctx context.Context, req *swarmrpc.ChangePwdRequest) (*swarmrpc.ChangePwdResponse, error) {
	// first we check the validaty of the old password
	err := u.readPassword(req.CurrentPassword)
	if err != nil {
		return nil, err
	}
	// Next we set the new password
	err = u.setPassword(req.NewPassword, true)
	if err != nil {
		return nil, err
	}
	if req.NewMacaroonRootKey || req.StatelessInit {
		for _, file := range u.macaroonFiles {
			err := os.Remove(file)
			if err != nil && !req.StatelessInit {
				return nil, fmt.Errorf("could not remove "+
					"macaroon file: %v. if the wallet "+
					"was initialized stateless please "+
					"add the --stateless_init "+
					"flag", err)
			}
		}
	}
	// Then we have to load the macaroon key-store, unlock it, change the old password and then shut it down
	macaroonService, err := macaroons.InitService(*u.macaroonDB, "bitswarmd", req.StatelessInit)
	if err != nil {
		return nil, err
	}
	err = macaroonService.CreateUnlock(&req.CurrentPassword)
	if err != nil {
		closeErr := macaroonService.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("could not create unlock: %v --> follow-up error when closing: %v", err, closeErr)
		}
		return nil, err
	}
	err = macaroonService.ChangePassword(req.CurrentPassword, req.NewPassword)
	if err != nil {
		closeErr := macaroonService.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("could not change password: %v --> follow-up error when closing: %v", err, closeErr)
		}
		return nil, err
	}
	err = macaroonService.Close()
	if err != nil {
		return nil, fmt.Errorf("could not close macaroon service: %v", err)
	}

	// We can now send the UnlockMsg through the channel
	select {
	case u.PassChan <- &PasswordMsg{Password: req.NewPassword, StatelessInit: req.StatelessInit, Err: nil}:
		// We hang until we receive the admin macaroon or a timeout error
		select {
		case adminMac := <-u.MacRespChan:
			return &swarmrpc.ChangePwdResponse{
				AdminMacaroon: adminMac,
			}, nil
		case <-ctx.Done():
			return nil, ErrUnlockTimeout
		}

	case <-ctx.Done():
		return nil, ErrUnlockTimeout
	}
}
```
For our CLI, we need to create a new file in `auth` called `macaroon_jar.go`. It will hold two helper functions `decryptMacaroon()` and `loadMacaroon()`. Essentially, we will load the admin macaroon file in memory, decrypt it, add a 60 second timeout constraint and then repackage it. The reason we do this is to prevent replay attacks.
```
package auth

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcwallet/snacl"
	macaroon "gopkg.in/macaroon.v2"
)

const (
	encryptionPrefix = "snacl:"
)

type getPasswordFunc func(prompt string) ([]byte, error)

// decryptMacaroon will take a password and derive the priv key using the provided password to then decrypt the macaroon
func decryptMacaroon(keyBase64, dataBase64 string, pw []byte) ([]byte, error) {
	keyData, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("Could not base64 decode encryption key: %v", err)
	}
	encryptedMac, err := base64.StdEncoding.DecodeString(dataBase64)
	if err != nil {
		return nil, fmt.Errorf("Could not base64 decode encrypted macaroon: %v", err)
	}
	key := &snacl.SecretKey{}
	err = key.Unmarshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshall encryption key: %v", err)
	}
	err = key.DeriveKey(&pw)
	if err != nil {
		return nil, fmt.Errorf("Could not derive encryption key possibly due to incorrect password: %v", err)
	}
	macBytes, err := key.Decrypt(encryptedMac)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt macaroon: %v", err)
	}
	return macBytes, nil
}

// loadMacaroon takes a password prompting function and hex encoded macaroon and returns an instantiated macaroon object
func loadMacaroon(pwCallback getPasswordFunc, macHex string) (*macaroon.Macaroon, error) {
	if len(strings.TrimSpace(macHex)) == 0 {
		return nil, fmt.Errorf("macaroon data is empty")
	}
	var (
		macBytes []byte
		err      error
	)
	if strings.HasPrefix(macHex, encryptionPrefix) {
		parts := strings.Split(macHex, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("Invalid encrypted macaroon. Format expected: 'snacl:<key_base64>:<encrypted_macaroon_base64>'")
		}
		pw, err := pwCallback("Enter macaroon encryption password: ")
		if err != nil {
			return nil, fmt.Errorf("Could not read password from terminal: %v", err)
		}
		macBytes, err = decryptMacaroon(parts[1], parts[2], pw)
		if err != nil {
			return nil, fmt.Errorf("Unable to decrypt macaroon: %v", err)
		}
	} else {
		macBytes, err = hex.DecodeString(macHex)
		if err != nil {
			return nil, fmt.Errorf("Unable to hex decode macaroon: %v", err)
		}
	}
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("Unable to decode macaroon: %v", err)
	}
	return mac, nil
}
```
Now we modify `auth/connection.go`
```
// GetClientConn returns the grpc Client connection for use in instantiating gRPC Clients
func GetClientConn(grpcServerAddr, grpcServerPort, tlsCertPath, adminMacPath string, skipMacaroons bool, macaroon_timeout int64) (*grpc.ClientConn, error) {
	//get TLS credentials from TLS certificate file
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}
	if !skipMacaroons {
		// grab Macaroon data and load it into macaroon.Macaroon struct
		adminMac, err := os.ReadFile(adminMacPath)
		if err != nil {
			return nil, fmt.Errorf("Could not read macaroon at %v: %v", adminMacPath, err)
		}
		macHex := hex.EncodeToString(adminMac)
		mac, err := loadMacaroon(ReadPassword, macHex)
		if err != nil {
			return nil, fmt.Errorf("Could not load macaroon; %v", err)
		}
		// Add constraints to our macaroon
		macConstraints := []macaroons.Constraint{
			macaroons.TimeoutConstraint(macaroon_timeout), // prevent a replay attack
		}
		constrainedMac, err := macaroons.AddConstraints(mac, macConstraints...)
		if err != nil {
			return nil, err
		}
		cred := macaroons.NewMacaroonCredential(constrainedMac)
		opts = append(opts, grpc.WithPerRPCCredentials(cred))
	}
	genericDialer := utils.ClientAddressDialer(grpcServerPort)
	opts = append(opts, grpc.WithContextDialer(genericDialer))
	opts = append(opts, grpc.WithDefaultCallOptions(maxMsgRecvSize))
	conn, err := grpc.Dial(grpcServerAddr+":"+grpcServerPort, opts...)
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to RPC server: %v", err)
	}
	return conn, nil
}

// readPassword reads a password from the terminal.
func ReadPassword(instruction string) ([]byte, error) {
	fmt.Print(instruction)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	if len(pw) == 0 {
		return nil, fmt.Errorf("Password cannot be blank")
	}
	fmt.Println()
	return pw, err
}
```
I've moved `readPassword()` from `commands_unlocker.go` to here and made it a public function. The only changes needed in `commands_unlocker.go` are to import the `auth` package, then change `readPassword()` to `auth.ReadPassword()` and add a `--new_mac_root_key` flag to the `changePassword` command. 

In `cmd/swarmcli/main.go` we will modify the functions that initialize the clients to use our newly modified `GetClientConn()` which has a few new arguments for macaroons.
```
type Args struct {
	RPCAddr      string
	RPCPort      string
	TLSCertPath  string
	AdminMacPath string
}
...
// getSwarmClient returns the SwarmClient instance from the swarmrpc package as well as a cleanup function
func getSwarmClient(ctx *cli.Context) (swarmrpc.SwarmClient, func()) {
	args := extractArgs(ctx)
	conn, err := auth.GetClientConn(args.RPCAddr, args.RPCPort, args.TLSCertPath, args.AdminMacPath, false, defaultMacaroonTimeout)
	if err != nil {
		fatal(err)
	}
	cleanUp := func() {
		conn.Close()
	}
	return swarmrpc.NewSwarmClient(conn), cleanUp
}
...
// extractArgs extracts the arguments inputted to the swarmcli command
func extractArgs(ctx *cli.Context) *Args {
	return &Args{
		RPCAddr:      ctx.GlobalString("rpc_addr"),
		RPCPort:      ctx.GlobalString("rpc_port"),
		TLSCertPath:  ctx.GlobalString("tlscertpath"),
		AdminMacPath: ctx.GlobalString("macaroonpath"),
	}
}

// main is the entrypoint for swarmcli
func main() {
	app := cli.NewApp()
	app.Name = "swarmcli"
	app.Usage = "Command Line tool for the Bitswarm Daemon (bitswarmd)"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "rpc_addr",
			Value: defaultRPCAddr,
			Usage: "The host address of the Bitswarm daemon (exclude the port)",
		},
		cli.StringFlag{
			Name:  "rpc_port",
			Value: defaultRPCPort,
			Usage: "The host port of the Bitswarm daemon",
		},
		cli.StringFlag{
			Name:      "tlscertpath",
			Value:     defaultTLSCertPath,
			Usage:     "The path to bitswarmd's TLS certificate.",
			TakesFile: true,
		},
		cli.StringFlag{
			Name:      "macaroonpath",
			Value:     defaultMacPath,
			Usage:     "The path to bitswarmd's macaroons.",
			TakesFile: true,
		},
	}
	app.Commands = []cli.Command{
		stopCommand,
		testCommand,
		setPassword,
		unlockCommand,
		changePassword,
	}
	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
```
We also added a `macaroonpath` flag for `swarmcli` in the event that macaroons are not in the AppData directory.

## Step 19: Macaroon/TLS Testing via Python and Curl

So now if we wanted to use our gRPC API, we would need the TLS certificate and a macaroon.
`Python`
```
import protos.swarm_pb2 as swarm
import protos.swarm_pb2_grpc as swarmrpc
import protos.unlocker_pb2 as unlocker
import protos.unlocker_pb2_grpc as unlockerrpc
import grpc
import os
import codecs

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

# Lnd admin macaroon is at ~/.lnd/data/chain/bitcoin/simnet/admin.macaroon on Linux and
# ~/Library/Application Support/Lnd/data/chain/bitcoin/simnet/admin.macaroon on Mac
with open(os.path.expanduser('~/Library/Application Support/Bitswarmd/admin.macaroon'), 'rb') as f:
    macaroon_bytes = f.read()
    macaroon = codecs.encode(macaroon_bytes, 'hex')

cert = open(os.path.expanduser('~/Library/Application Support/Bitswarmd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:4567', creds)
stub = swarmrpc.SwarmStub(channel)
response = stub.TestCommand(swarm.TestRequest(), metadata=[('macaroon', macaroon)])
print(response)
```
`curl`
```
$ MACAROON_HEADER="Grpc-Metadata-macaroon: $(xxd -ps -u -c 1000 ~/Library/Application\ Support/Bitswarmd/admin.macaroon)"
$ curl -X GET --cacert ~/Library/Application\ Support/Bitswarmd/tls.cert --header "$MACAROON_HEADER" https://localhost:8080/v1/test
{"msg":"This is a regular test"}$
```
## Step 20: Adding New Commands/API Endpoints

At this stage, we have a fully functional API layer complete with TLS transport security, macaroon authentication and our daemon is password protected. But the daemon doesn't do a whole lot else. At this point, it's up to you to decide what you want your daemon to do. It could be hooked up to a bunch of temperature sensors and stream data in real-time. It could be the daemon for some cool new decentralized social media protocol. The possibilities are endless. As a final step, I will go through the process of creating a new command from start to finish. To make it a bit more interesting, the test command will be a server side streamed response and I will also modify the test macaroon to only be useable for that specific type of command.

So the first thing to change is `swarm.proto`
```
syntax = "proto3";

package swarmrpc;

option go_package = "gitlab.com/cypher-engineers/bitswarmd/swarmrpc";

// Swarm is the main RPC server of the daemon.
service Swarm {
    /* swarmcli: `stop`
    StopDaemon will send a shutdown request to the interrupt handler, triggering
    a graceful shutdown of the daemon.
    */
    rpc StopDaemon (StopRequest) returns (StopResponse);
    /* swarmcli: `test`
    TestCommand will send a string response regardless if a macaroon is provided or not.
    */
    rpc TestCommand (TestRequest) returns (TestResponse);
    /* swarmcli: `admintest`
    AdminTest will send a string response only if a macaroon is provided.
    */
    rpc AdminTest (AdminTestRequest) returns (stream AdminTestResponse);
}

message StopRequest {
}
message StopResponse {
}
message TestRequest {
}
message TestResponse {
    string msg = 1;
}
message AdminTestRequest {
}
message AdminTestResponse {
    string msg = 1;
}
```
Then we also modify `swarm.yaml`
```
type: google.api.Service
config_version: 3

http:
  rules:
    - selector: swarmrpc.Swarm.StopDaemon
      get: "/v1/stop"
    - selector: swarmrpc.Swarm.TestCommand
      get: "/v1/test"
    - selector: swarmrpc.Swarm.AdminTest
      get: "/v1/admintest"
```
Then we regenerate our stubs `$ ./gen_protos.sh -y swarm.yaml -p swarm.proto`. We will now implement our new command in `rpcserver.go`. It will quite simply just send 10 `AdminTestResponse` objects in a loop.
```
// MainRPCServerPermissions returns a mapping of the main RPC server calls to
// the permissions they require.
func MainRPCServerPermissions() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		"/swarmrpc.Swarm/StopDaemon": {{
			Entity: "swarm",
			Action: "write",
		}},
		"/swarmrpc.Swarm/TestCommand": {{
			Entity: "swarm",
			Action: "read",
		}},
		"/swarmrpc.Swarm/AdminTest": {{
			Entity: "swarm",
			Action: "read",
		}},
	}
}
...
// AdminTest will return a stream of responses provided a specific macaroon
func (r *RpcServer) AdminTest(_ *swarmrpc.AdminTestRequest, updateStream swarmrpc.Swarm_AdminTestServer) error {
	for i := 0; i < 10; i++ {
		select {
		case <-updateStream.Context().Done():
			if errors.Is(updateStream.Context().Err(), context.Canceled) {
				return nil
			}
			return updateStream.Context().Err()
		default:
			msg := "Test string %v"
			object := &swarmrpc.AdminTestResponse{
				Msg: fmt.Sprintf(msg, i),
			}
			if err := updateStream.Send(object); err != nil {
				return err
			}
		}
	}
	return nil
}
```
Now we will do a quick little modification to `Main()` in `bitswarm.go`. I want to show the true power of macaroons. So far, we've only used the admin macaroon. If you've studied the macaroon generation portion of `Main()`, you may have noticed, we also bake a `test.macaroon` and it specifically only has read permissions and only lasts 120 seconds. That means that any command with write permission, could not be used by this macaroon. It also means that 120 seconds after it's creation, it can no longer be used. I'm going to generate a third macaroon. It will be write-only and also expire 120 seconds after creation. In our test, I will prove what I just mentioned by using both these macaroons.
```
func Main() {
	...
	if !macaroonService.StatelessInit &&
		!utils.FileExists(server.cfg.AdminMacPath) &&
		!utils.FileExists(server.cfg.TestMacPath) {
		err := genMacaroons(
			ctx, macaroonService, server.cfg.AdminMacPath, adminPermissions(), false, 0,
		)
		if err != nil {
			server.logger.Error().Msg(fmt.Sprintf("Unable to create admin macaroon: %v", err))
			return err
		}
		err = genMacaroons(
			ctx, macaroonService, server.cfg.TestMacPath, readPermissions, true, 120,
		)
		if err != nil {
			server.logger.Error().Msg(fmt.Sprintf("Unable to create test macaroon: %v", err))
			return err
		}
		err = genMacaroons(
			ctx, macaroonService, utils.AppDataDir("bitswarmd", false)+"/write.macaroon", writePermissions, true, 120,
		)
		if err != nil {
			server.logger.Error().Msg(fmt.Sprintf("Unable to create test macaroon: %v", err))
			return err
		}
		server.logger.Info().Msg("Macaroons baked successfully.")
	}
	...
}
```
Let's quickly delete all our macaroons so they can be regenerated before we get ahead of ourselves and forget to do so. Finally, we will implement the command in our CLI for completeness.
`commands.go`
```
var adminTestCommand = cli.Command{
	Name:  "admintest",
	Usage: "Test command that returns a server side, streamed response",
	Description: `
	A test command that returns a streamed response.`,
	Action: adminTest,
}

// adminTest implements the gRPC AdminTest command
func adminTest(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getSwarmClient(ctx)
	defer cleanUp()
	stream, err := client.AdminTest(ctxc, &swarmrpc.AdminTestRequest{})
	if err != nil {
		return err
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		printRespJSON(resp)
	}
	return nil
}
```
Don't forget to add this command to the list of commands in `main.go`
```
func main() {
	...
	app.Commands = []cli.Command{
		stopCommand,
		testCommand,
		setPassword,
		unlockCommand,
		changePassword,
		adminTestCommand,
	}
	...
}
```
Before we test our new command, let's edit our Python file so that our macaroons don't expire before we are ready to use them. You must also copy the new `swarm.proto` file over to Python and regenerate the Python stubs in order to use the new command.
```
import protos.swarm_pb2 as swarm
import protos.swarm_pb2_grpc as swarmrpc
import protos.unlocker_pb2 as unlocker
import protos.unlocker_pb2_grpc as unlockerrpc
import grpc
import os
import codecs

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

# Lnd admin macaroon is at ~/.lnd/data/chain/bitcoin/simnet/admin.macaroon on Linux and
# ~/Library/Application Support/Lnd/data/chain/bitcoin/simnet/admin.macaroon on Mac
with open(os.path.expanduser('~/Library/Application Support/Bitswarmd/test.macaroon'), 'rb') as f:
    macaroon_bytes = f.read()
    macaroon_read = codecs.encode(macaroon_bytes, 'hex')

with open(os.path.expanduser('~/Library/Application Support/Bitswarmd/write.macaroon'), 'rb') as f:
    macaroon_bytes = f.read()
    macaroon_write = codecs.encode(macaroon_bytes, 'hex')

cert = open(os.path.expanduser('~/Library/Application Support/Bitswarmd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:4567', creds)
stub = swarmrpc.SwarmStub(channel)
response = stub.TestCommand(swarm.TestRequest(), metadata=[('macaroon', macaroon_read)])
print(response)

# This shouldn't work
for resp in stub.AdminTest(swarm.AdminTestRequest(), metadata=[('macaroon', macaroon_write)]):
    print(resp)
#This should 
for resp in stub.AdminTest(swarm.AdminTestRequest(), metadata=[('macaroon', macaroon_read)]):
    print(resp)
```
`Client`
```
$ python grpc_testing.py
msg: "This is a regular test"

Traceback (most recent call last):
  File "grpc_test.py", line 32, in <module>
    for resp in stub.AdminTest(swarm.AdminTestRequest(), metadata=[('macaroon', macaroon_write)]):
  File "~/go/src/gitlab.com/cypher-engineers/grpc_testing/venv/lib/python3.7/site-packages/grpc/_channel.py", line 426, in __next__
    return self._next()
  File "~/go/src/gitlab.com/cypher-engineers/grpc_testing/venv/lib/python3.7/site-packages/grpc/_channel.py", line 826, in _next
    raise self
grpc._channel._MultiThreadedRendezvous: <_MultiThreadedRendezvous of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "permission denied"
        debug_error_string = "{"created":"@1643492512.290320000","description":"Error received from peer ipv6:[::1]:4567","file":"src/core/lib/surface/call.cc","file_line":1075,"grpc_message":"permission denied","grpc_status":2}"
>
```
`Server`
```
4:41PM [ERROR]   [/swarmrpc.Swarm/AdminTest]: permission denied subsystem=RPCS
```
Then we comment out the first for loop and it works
```
# This shouldn't work
# for resp in stub.AdminTest(swarm.AdminTestRequest(), metadata=[('macaroon', macaroon_write)]):
#    print(resp)
#This should 
for resp in stub.AdminTest(swarm.AdminTestRequest(), metadata=[('macaroon', macaroon_read)]):
    print(resp)
```
`Client`
```
$ python grpc_test.py 
msg: "This is a regular test"

msg: "Test string 0"

msg: "Test string 1"

msg: "Test string 2"

msg: "Test string 3"

msg: "Test string 4"

msg: "Test string 5"

msg: "Test string 6"

msg: "Test string 7"

msg: "Test string 8"

msg: "Test string 9"
```
If we wait 120 seconds, we can see the macaroon expire in our client-side and server-side responses.
`Client`
```
$ python grpc_test.py 
Traceback (most recent call last):
  File "grpc_test.py", line 28, in <module>
    response = stub.TestCommand(swarm.TestRequest(), metadata=[('macaroon', macaroon_read)])
  File "~/go/src/gitlab.com/cypher-engineers/grpc_testing/venv/lib/python3.7/site-packages/grpc/_channel.py", line 946, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "~/go/src/gitlab.com/cypher-engineers/grpc_testing/venv/lib/python3.7/site-packages/grpc/_channel.py", line 849, in _end_unary_response_blocking
    raise _InactiveRpcError(state)
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "caveat "time-before 2022-01-29T21:45:25.663859Z" not satisfied: macaroon has expired"
        debug_error_string = "{"created":"@1643492781.816091000","description":"Error received from peer ipv6:[::1]:4567","file":"src/core/lib/surface/call.cc","file_line":1075,"grpc_message":"caveat "time-before 2022-01-29T21:45:25.663859Z" not satisfied: macaroon has expired","grpc_status":2}"
>
```
`Server`
```
4:46PM [ERROR]   [/swarmrpc.Swarm/TestCommand]: caveat "time-before 2022-01-29T21:45:25.663859Z" not satisfied: macaroon has expired subsystem=RPCS
```
But then our CLI uses the admin macaroon so we get the expected response
```
$ swarmcli admintest
{
    "msg":  "Test string 0"
}
{
    "msg":  "Test string 1"
}
{
    "msg":  "Test string 2"
}
{
    "msg":  "Test string 3"
}
{
    "msg":  "Test string 4"
}
{
    "msg":  "Test string 5"
}
{
    "msg":  "Test string 6"
}
{
    "msg":  "Test string 7"
}
{
    "msg":  "Test string 8"
}
{
    "msg":  "Test string 9"
}
```
That's the magic of macaroons.

## Conclusion

This concludes the *LND Under the Hood* series. If you made it this far, I thank you for struggling through this with me. It definitely was not an easy exercise to disect this monolithic codebase but it certainly was insightful. The sad part is that I've barely scratched the surface of how LND actually works. This is just the foundation fthat all the LND related services sit on top of. My hope with this series is that more people decide to code with go and that more people build tools that can benefit humanity like LND and Bitcoin do. 