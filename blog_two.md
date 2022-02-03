# LND Under the Hood Part 2: Integrating gRPC and REST Services

## Introduction

Welcome back to the *LND Under the Hood* series. In this second part, we will look at how to write our own proto file, generate the protobufs using `protoc`, integrating gRPC, making gRPC calls using a command line tool as well as from a Python script, integrating gRPC middleware for logging and future authentication and finally adding a REST to gRPC proxy.

## Step 5: Proto File

gRPC is an API framework, different from REST because it uses protocol buffers. Both the client and the server know what kind of data they will send and receive ahead of time. It's also a much more performant framework and easily integrates bi-directional streaming. 

In this step we will write a basic `.proto` file containg just two commands. We will define a `StopDaemon()` command and a `TestCommand()` command. The `swarm.proto` file will be placed in the `swarmrpc` directory, equivalent to the `lightning.proto` file and the `lnrpc` directory respectively. To learn more about the proto language, there's some useful information [here](https://developers.google.com/protocol-buffers/docs/proto3) but just know that when `protoc` reads this file, it will generate go files.

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
```
I chose to respect the comment convention that LND has in its proto files, indicating how this RPC command is invoked with the cli tool. I think it's useful for anyone trying to understand how the command line invokes commands on the daemon.

To generate the go files, we use this command

```
$ protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative swarm.proto
```
To avoid having to constantly look up this command, you can also create a bash script with a flag for the proto file name
`gen_protos.sh`
```
while getopts p: flag
do
    case "${flag}" in
        p) proto=${OPTARG};;
    esac
done

protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $proto
```
Don't forget to `sudo chmod +x gen_protos.sh` to make it executable. Then you should be able to `./gen_protos.sh -p swarm.proto` to get the same result. You should now have two new go files in the directory: `swarm_grpc.pb.go` and `swarm.pb.go` where instead of `swarm` you have whatever you named your `.proto` file. We are now ready to implement a gRPC server which will use these generated files.

## Step 6: Implementing the gRPC Server

Implementing a gRPC server is really easy now that we've generated the protos. All we have to do is create a struct which implements `UnimplementedSwarmServer` from the `swarm_grpc.pb.go` file. We must make sure our new struct has two methods called `StopDaemon()` and `TestCommand()` or it will not be properly implemented.

I've created a file called `rpcserver.go` in the `bitswarm` package.

```
package bitswarm

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/rs/zerolog"
	"gitlab.com/cypher-engineers/bitswarmd/intercept"
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	"google.golang.org/grpc"
)

// RpcServer is a child of the swarmrpc.UnimplementedSwarmServer struct. Meant to host all related attributes to the rpcserver
type RpcServer struct {
	Running int32 // used atomically
	swarmrpc.UnimplementedSwarmServer
	interceptor *intercept.Interceptor
	cfg         *Config
	logger      *zerolog.Logger
	Listener    net.Listener
}

// NewRpcServer creates an instance of the GrpcServer struct
func NewRpcServer(interceptor *intercept.Interceptor, config *Config, log *zerolog.Logger) (*RpcServer, error) {
	listener, err := net.Listen("tcp", ":"+strconv.FormatInt(config.GrpcPort, 10))
	if err != nil {
		return nil, fmt.Errorf("Couldn't open tcp listener on port %v: %v", config.GrpcPort, err)
	}
	return &RpcServer{
		interceptor: interceptor,
		cfg:         config,
		logger:      log,
		Listener:    listener,
	}, nil
}

// Start starts the server. Returns an error if any issues occur
func (r *RpcServer) Start() error {
	r.logger.Info().Msg("Starting RPC server...")
	if ok := atomic.CompareAndSwapInt32(&r.Running, 0, 1); !ok {
		return fmt.Errorf("Could not start RPC server: server already started.")
	}
	return nil
}

// Stop stops the server. Returns an error if any issues occur
func (r *RpcServer) Stop() error {
	r.logger.Info().Msg("Stopping RPC server...")
	if ok := atomic.CompareAndSwapInt32(&r.Running, 1, 0); !ok {
		return fmt.Errorf("Could not stop RPC server: server already stopped.")
	}
	return nil
}

// RegisterWithGrpcServer registers the rpcServer with the root gRPC server.
func (r *RpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	swarmrpc.RegisterSwarmServer(grpcServer, r)
	return nil
}

// StopDaemon will send a shutdown request to the interrupt handler, triggering a graceful shutdown
func (r *RpcServer) StopDaemon(_ context.Context, _ *swarmrpc.StopRequest) (*swarmrpc.StopResponse, error) {
	r.interceptor.RequestShutdown()
	return &swarmrpc.StopResponse{}, nil
}

// TestCommand will return a string for any macaroon
func (r *RpcServer) TestCommand(_ context.Context, _ *swarmrpc.TestRequest) (*swarmrpc.TestResponse, error) {
	return &swarmrpc.TestResponse{Msg: "This is a regular test"}, nil
}
```

To create a new `RpcServer`, we must give it the interceptor. This is because we want our `StopDaemon()` command to execute a graceful shutdown of the daemon and to do this we trigger the interceptor. You may also notice that our implementations of the commands take in a context and request argument but they aren't used. This is because in our `proto` definition of those commands, we didn't specify any parameters for `StopRequest` and `TestRequest` but we could have if we wanted to. In which case, we would then use the request argument.

You may have noticed that our `RpcServer` is expecting the `Config` to have a `GrpcPort` attribute, which it currently does not. So we will quickly change that.

```
type Config struct {
	...
	GrpcPort      int64  `yaml:"GrpcPort"`
}

var (
	...
	default_grpc_port int64 = 4567
	default_config          = func() Config {
		return Config{
			DefaultLogDir: true,
			LogFileDir:    default_log_dir(),
			ConsoleOutput: true,
			GrpcPort:      default_grpc_port,
		}
	}
)

...
func check_yaml_config(config Config) Config {
    ...
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		field_name := field_names.Field(i).Name
		switch field_name {
		case "LogFileDir":
			...
		case "GrpcPort":
			if f.Int() == 0 {
				change_field(f, default_grpc_port)
			}
		}
	}
	return config
}
```

Before we continue with gRPC, we will quickly create a public function in `log.go` to make it easier to create new subloggers for our sub servers. It's more useful for debugging this way.

```
// NewSubLogger takes a `zerolog.Logger` and string for the name of the subsystem and creates a `subLogger` for this subsystem
func NewSubLogger(l *zerolog.Logger, subsystem string) *zerolog.Logger {
	sub := l.With().Str("subsystem", subsystem).Logger()
	return &sub
}
```

Now we will modifiy the `Main()` function of `bitswarm.go` to instantiate our `RpcServer` struct, register it with a gRPC server and start listening on a specified port.

```
func Main() {
    ...
    // Instantiating RPC server
	rpcServer, err := NewRpcServer(interceptor, server.cfg, NewSubLogger(server.logger, "RPCS"))
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize RPC server: %v", err))
		return err
	}
	server.logger.Info().Msg("RPC Server Initialized.")

	// Creating gRPC server and Server options
	var serverOpts []grpc.ServerOption
	grpc_server := grpc.NewServer(serverOpts...)
	rpcServer.RegisterWithGrpcServer(grpc_server)

	//Starting RPC and gRPC Servers
	server.logger.Info().Msg("Starting RPC server...")
	err = rpcServer.Start()
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not start RPC server: %v", err))
		return err
	}
	defer rpcServer.Stop()
	server.logger.Info().Msg("RPC Server Started")

	// start gRPC listening
	err = startGrpcListen(grpc_server, rpcServer.Listener)
	if err != nil {
		rpcServer.logger.Fatal().Msg(fmt.Sprintf("Could not start gRPC listen on %v:%v", rpcServer.Listener.Addr(), err))
		return err
	}
	rpcServer.logger.Info().Msg(fmt.Sprintf("gRPC listening on %v", rpcServer.Listener.Addr()))

    // Listen for shutdown signals
	<-interceptor.ShutdownChannel()
	return nil
}
```

Finally, we will create a `startGrpcListen()` function to start listening for gRPC requests on the given port. The gRPC server is started in a separate go routine because eventually, we may have many gRPC servers listening on multiple ports and doing so will speed up the process.

```
// startGrpcListen starts the gRPC listening on given ports
func startGrpcListen(grpcServer *grpc.Server, listener net.Listener) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func(lis net.Listener) {
		wg.Done()
		_ = grpcServer.Serve(lis)
	}(listener)
	wg.Wait()
	return nil
}
```

Now if we compile and run our code, we should be able to test both commands using a Python script! The next step will describe how to do this. If you're already familiar with how to write gRPC client code in Python, then feel free to skip to step 8.

## Step 7: Testing with a Python Script

To test our newly created gRPC server, we will build a simple gRPC client from our proto file we created earlier. Move to a completely separate directory from your project, create a virtual environment `$ python -m venv venv` and activate it `source venv/bin/activate`. Then create a `protos` directory and copy/paste the `swarm.proto` file over to the newly created directory `mkdir protos && cp /path/to/proto/swarm.proto protos/`. Finally, install the following packages using `pip`
```
$ pip install grpcio grpcio-tools googleapis-common-protos
```
Navigate to the `protos` directory and clone this github repository `git clone https://github.com/googleapis/googleapis.git`. Instead of using `protoc` we will use a python script to generate the stubs in the python language. The github repository is needed for this. Finally we generate the stubs via the following command
```
$ python -m grpc_tools.protoc --proto_path=googleapis:. --python_out=. --grpc_python_out=. swarm.proto
```
We will now modify the `_grpc.py` stub file because it has the other stub file as a dependency but it doesn't import this file via the `protos` package. It's a simple fix, just add `protos.` to the import statement as such
```
import protos.swarm_pb2 as swarm__pb2
```

You will notice that the stub files have comments telling you not to modify these files. That advice should be heeded 99% of the time. Changing the import statement is a 1% of the time case. There is probably a way to modify to `proto` file or pass an argument into the stub generation command to avoid this but I'm currently unaware of that.

Now backing out of the `protos` directory, we will create a new python file called `grpc_test.py`. The following lines of code are added
```
import protos.swarm_pb2 as swarm
import protos.swarm_pb2_grpc as swarmrpc
import grpc
import os

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

channel = grpc.insecure_channel('localhost:4567')
stub = swarmrpc.SwarmStub(channel)

response = stub.TestCommand(swarm.TestRequest())
print(response.msg)
```
At last, we can test our gRPC server by running `python grpc_test.py`. If all has been done properly, the python script should print `This is a regular test` in the command prompt. You can also test the `StopDaemon()` command though the response it returns is empty.

## Step 8: Swarmcli

Creating scripts in other languages to test our gRPC server is a nice trick but for actual usage, it becomes a bit cumbersome. Instead, we can use a command line tool that we will create. To begin, let's populate the `main.go` file within the `cmd/swarmcli` directory.

```
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli"
	"gitlab.com/cypher-engineers/bitswarmd/auth"
	"gitlab.com/cypher-engineers/bitswarmd/bitswarm"
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	"google.golang.org/grpc"
)

// fatal exits the process and prints out error information
func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[swarmcli] %v\n", err)
	os.Exit(1)
}

// getSwarmClient returns the SwarmClient instance from the swarmrpc package as well as a cleanup function
func getSwarmClient(ctx *cli.Context) (swarmrpc.SwarmClient, func()) {
	args := extractArgs(ctx)
	conn, err := auth.GetClientConn(args.RPCAddr, args.RPCPort)
	if err != nil {
		fatal(err)
	}
	cleanUp := func() {
		conn.Close()
	}
	return swarmrpc.NewSwarmClient(conn), cleanUp
}

// extractArgs extracts the arguments inputted to the lncli command
func extractArgs(ctx *cli.Context) *Args {
	return &Args{
		RPCAddr: ctx.GlobalString("rpc_addr"),
		RPCPort: ctx.GlobalString("rpc_port"),
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
Just like with LND, we will use the `cli` library built by `urfave`. Other than `main` there are some other, private functions that are not being used at the moment: namely, `getSwarmClient()`. Our CLI will act as a gRPC client and so this function will help us build that client. Notice that we defined two arguments for our CLI tool. If no args are passed, default values are set.

You may have noticed a new package called `auth`. We will now create a file called `connection.go` in this package and define `GetClientConn()`.
```
package auth

import (
	"fmt"

	"gitlab.com/cypher-engineers/bitswarmd/utils"
	"google.golang.org/grpc"
)

var (
	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200)
)

// GetClientConn returns the grpc Client connection for use in instantiating gRPC clients
func GetClientConn(grpcServerAddr, grpcServerPort string) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
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
Our new `GetClientConn()` creates a client connection to our gRPC server using some custom dial options. One of these dial options relies on `ClientAddressDialer()` which we will define in the `utils` package. We will create two files in the utils package; one called `address.go`, the other `address_test.go`. Most of this code was copied from LND and reworked to fit this project. Feel free to look through this code but know that it's largely just a bunch of helper code to work with different address types.
`address.go`
```
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
```
`address_test.go`
```
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
```
With this in place, we are almost ready to compile and test our CLI. We just need to define `stopCommand` and `testCommand`. In the `cmd/swarmcli` directory, we will populate the `commands.go` file with our commands.

```
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli"
	"gitlab.com/cypher-engineers/bitswarmd/intercept"
	"gitlab.com/cypher-engineers/bitswarmd/swarmrpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// getContext spins up a go routine to monitor for shutdown requests and returns a context object
func getContext() context.Context {
	shutdownInterceptor, err := intercept.InitInterceptor()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctxc, cancel := context.WithCancel(context.Background())
	go func() {
		<-shutdownInterceptor.ShutdownChannel()
		cancel()
	}()
	return ctxc
}

// printRespJSON will convert a proto response as a string and print it
func printRespJSON(resp proto.Message) {
	jsonMarshaler := &protojson.MarshalOptions{
		Multiline:     true,
		UseProtoNames: true,
		Indent:        "    ",
	}
	jsonStr := jsonMarshaler.Format(resp)
	fmt.Println(jsonStr)
}

var stopCommand = cli.Command{
	Name:  "stop",
	Usage: "Stop and shutdown the daemon",
	Description: `
	Gracefully stop all daemon subprocesses before stopping the daemon itself. This is equivalent to stopping it using CTRL-C.`,
	Action: stopDaemon,
}

// stopDaemon is the proxy command between swarmcli and gRPC equivalent.
func stopDaemon(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getSwarmClient(ctx) //This command returns the proto generated SwarmClient instance
	defer cleanUp()

	_, err := client.StopDaemon(ctxc, &swarmrpc.StopRequest{})
	if err != nil {
		return err
	}
	return nil
}

var testCommand = cli.Command{
	Name:  "test",
	Usage: "Test command",
	Description: `
	A test command which returns a string for any macaroon provided.`,
	Action: test,
}

// Proxy command for the swarmcli
func test(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getSwarmClient(ctx)
	defer cleanUp()
	testResp, err := client.TestCommand(ctxc, &swarmrpc.TestRequest{})
	if err != nil {
		return err
	}
	printRespJSON(testResp)
	return nil
}
```
A couple of noteworthy things: we use a SIGINT signal interceptor here in the case where the CLI hangs when making a gRPC call and the user wishes to cancel. There is also a response parser function `printRespJSON()` to print the gRPC response as a JSON string. Finally, we declare our commands. The commands are `cli.Command` structs where the `Action` field is a callback to the actual function it will execute. The general structure for these command actions is to get a gRPC Client, build the Request struct, make the gRPC call and print the response. Pretty easy. LND has more complex examples using this library where flags and command line arguments are needed to properly execute the commands.

We are now able to test our CLI. We will build
```
$ GO111MODULE=on go install -v gitlab.com/cypher-engineers/bitswarmd/cmd/bitswarmd
$ GO111MODULE=on go install -v gitlab.com/cypher-engineers/bitswarmd/cmd/swarmcli
```
spin up our daemon
```
$ bitswarmd
5:14PM [INFO]    Starting daemon...
5:14PM [INFO]    RPC Server Initialized.
5:14PM [INFO]    Starting RPC server... subsystem=RPCS
5:14PM [INFO]    RPC server started subsystem=RPCS
5:14PM [INFO]    gRPC listening on [::]:4567 subsystem=RPCS
```
and run `test` in another terminal
```
$ swarmcli test
{
    "msg":  "This is a regular test"
}
$ swarmcli stop
$
```

## Step 9: Adding gRPC Middleware

Server side error messages from gRPC are not appearing in our logs. We can change that by adding gRPC middleware, which will write any error messages to the logs. This middleware will also be used for macaroon authentication in the future. For now, we focus on capturing errors in our logs.

Let's create a new file in the `intercept` package called `grpc_intercept.go`. We will largely be copying the `interceptor.go` file in LNDs `rpcperms` package for this and adpating it for our needs, namely changing the accepted logger.

```
package intercept

import (
	"context"
	"fmt"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// GrpcInteceptor struct is a data structure with attributes relevant to creating the gRPC interceptor
type GrpcInterceptor struct {
	noMacaroons bool
	log         *zerolog.Logger
}

// NewGrpcInterceptor instantiates a new GrpcInterceptor struct
func NewGrpcInterceptor(log *zerolog.Logger, noMacaroons bool) *GrpcInterceptor {
	return &GrpcInterceptor{
		noMacaroons: noMacaroons,
		log:         log,
	}
}

// CreateGrpcOptions creates a array of gRPC interceptors
func (i *GrpcInterceptor) CreateGrpcOptions() []grpc.ServerOption {
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var strmInterceptors []grpc.StreamServerInterceptor
	// add the log interceptors
	unaryInterceptors = append(
		unaryInterceptors, logUnaryServerInterceptor(i.log),
	)
	strmInterceptors = append(
		strmInterceptors, logStreamServerInterceptor(i.log),
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

// logUnaryServerInterceptor is a simple UnaryServerInterceptor that will
// automatically log any errors that occur when serving a client's unary
// request.
func logUnaryServerInterceptor(log *zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("[%v]: %v", info.FullMethod, err))
		}
		return resp, err
	}
}

// logStreamServerInterceptor is a simple StreamServerInterceptor that
// will log any errors that occur while processing a client or server streaming
// RPC.
func logStreamServerInterceptor(log *zerolog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := handler(srv, ss)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("[%v]: %v", info.FullMethod, err))
		}
		return err
	}
}
```
I've cut out quite a bit from LNDs version of the gRPC interceptor, like the mutex locking, the quit channel, the macaroon stuff. Some of this stuff will come into play later, but for now this barebones middleware will do what we need it to do.

We can now modifiy the `Main()` function in `bitswarm.go` to add our middleware to the gRPC server.
```
func Main(interceptor *intercept.Interceptor, server *Server) error {
	...

	// Creating gRPC server and Server options
	var serverOpts []grpc.ServerOption
	grpc_interceptor := intercept.NewGrpcInterceptor(rpcServer.logger, false)
	rpcServerOpts := grpc_interceptor.CreateGrpcOptions()
	serverOpts = append(serverOpts, rpcServerOpts...)
	grpc_server := grpc.NewServer(serverOpts...)
	rpcServer.RegisterWithGrpcServer(grpc_server)

	...
}
```
Testing this is a bit tricky since we aren't using TLS nor are we using macaroon authentication. Provoking an error with our simple commands is challenging. At the momment, we will hold off testing the middleware. In the next part, we will integrate TLS and test making a gRPC request without providing a valid TLS certificate. This will yield an error message.

## Step 10: REST to gRPC Proxy

The final thing we are going to do in this part of *LND Under The Hood* is to add a REST proxy. Although gRPC is a great API framework, adoption is quite slow. And for many use cases, REST is still prefered. So why limit ourselves to gRPC when there's a somewhat simple way to add a REST proxy?

The first thing to do is to install some dependencies so that we can generate REST proxy files from our proto file.
```
$ go get github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
     github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
     google.golang.org/protobuf/cmd/protoc-gen-go \
     google.golang.org/grpc/cmd/protoc-gen-go-grpc
```

Next we will create a new YAML file in the `swarmrpc` package called `swarm.yaml`. For organizational purposes, we will give the YAML file the same name as our previously created proto file. The YAML file is needed for generating the OpenAPI swagger JSON file and the proxy go file. 
```
type: google.api.Service
config_version: 3

http:
  rules:
    - selector: swarmrpc.Swarm.StopDaemon
      get: "/v1/stop"
    - selector: swarmrpc.Swarm.TestCommand
      get: "/v1/test"
```
The naming scheme in the `selector` parameter is important to follow: packagename.Servicename.Commandname. We can now generate the REST proxy files.
```
$ protoc --grpc-gateway_out=. --grpc-gateway_opt=logtostderr=true --grpc-gateway_opt=paths=source_relative --grpc-gateway_opt=grpc_api_configuration=swarm.yaml swarm.proto
$ protoc --openapiv2_out=. --openapiv2_opt=logtostderr=true --openapiv2_opt=grpc_api_configuration=swarm.yaml --openapiv2_opt=json_names_for_fields=false swarm.proto
```
We can modify our bash script to be able to more easily generate our stub and REST proxy files in the future.
```
while getopts p:y: flag
do
    case "${flag}" in
        p) proto=${OPTARG};;
        y) yaml=${OPTARG};;
    esac
done

protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $proto
protoc --grpc-gateway_out=. --grpc-gateway_opt=logtostderr=true --grpc-gateway_opt=paths=source_relative --grpc-gateway_opt=grpc_api_configuration=$yaml $proto
protoc --openapiv2_out=. --openapiv2_opt=logtostderr=true --openapiv2_opt=grpc_api_configuration=$yaml --openapiv2_opt=json_names_for_fields=false $proto
```
We will also create another file in the `swarmrpc` package called `websocket_proxy.go`. This allows for the streaming gRPC responses to be exposed via our REST proxy. As the comments in the equivalent LND file suggest, this is based on a package called [grpc-websocket-proxy](https://github.com/tmc/grpc-websocket-proxy/)
```
package swarmrpc

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"golang.org/x/net/context"
)

const (
	MethodOverrideParam        = "method"
	HeaderWebSocketProtocol    = "Sec-Websocket-Protocol"
	WebSocketProtocolDelimiter = "+"
)

var (
	BitswarmdClientStreamingURIs = []*regexp.Regexp{}
	defaultHeadersToForward      = map[string]bool{
		"Origin":                 true,
		"Referer":                true,
		"Grpc-Metadata-Macaroon": true,
	}
	defaultProtocolsToAllow = map[string]bool{
		"Grpc-Metadata-Macaroon": true,
	}
)

type WebsocketProxy struct {
	backend             http.Handler
	logger              *zerolog.Logger
	upgrader            *websocket.Upgrader
	clientStreamingURIs []*regexp.Regexp
	pingInterval        time.Duration
	pongWait            time.Duration
}

type requestForwardingReader struct {
	io.Reader
	io.Writer

	pipeR *io.PipeReader
	pipeW *io.PipeWriter
}

type responseForwardingWriter struct {
	io.Writer
	*bufio.Scanner

	pipeR *io.PipeReader
	pipeW *io.PipeWriter

	header http.Header
	code   int
	closed chan bool
}

// NewWebSocketProxy attempts to expose the underlying handler as a response-
// streaming WebSocket stream with newline-delimited JSON as the content
// encoding. If pingInterval is a non-zero duration, a ping message will be
// sent out periodically and a pong response message is expected from the
// client. The clientStreamingURIs parameter can hold a list of all patterns
// for URIs that are mapped to client-streaming RPC methods. We need to keep
// track of those to make sure we initialize the request body correctly for the
// underlying grpc-gateway library.
func NewWebSocketProxy(h http.Handler, logger *zerolog.Logger, pingInterval, pongWait time.Duration) http.Handler {
	p := &WebsocketProxy{
		backend: h,
		logger:  logger,
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		clientStreamingURIs: BitswarmdClientStreamingURIs,
	}
	if pingInterval > 0 && pongWait > 0 {
		p.pingInterval = pingInterval
		p.pongWait = pongWait
	}
	return p
}

// pingPongEnabled returns true if a ping interval is set to enable sending and
// expecting regular ping/pong messages.
func (p *WebsocketProxy) pingPongEnabled() bool {
	return p.pingInterval > 0 && p.pongWait > 0
}

// ServeHTTP handles the incoming HTTP request. If the request is an
// "upgradeable" WebSocket request (identified by header fields), then the
// WS proxy handles the request. Otherwise the request is passed directly to the
// underlying REST proxy.
func (p *WebsocketProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		p.backend.ServeHTTP(w, r)
		return
	}
	p.upgradeToWebSocketProxy(w, r)
}

// upgradeToWebSocketProxy upgrades the incoming request to a WebSocket, reads
// one incoming message then streams all responses until either the client or
// server quit the connection.
func (p *WebsocketProxy) upgradeToWebSocketProxy(w http.ResponseWriter,
	r *http.Request) {

	conn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error().Msg(fmt.Sprintf("error upgrading websocket: %v", err))
		return
	}
	defer func() {
		err := conn.Close()
		if err != nil && !IsClosedConnError(err) {
			p.logger.Error().Msg(fmt.Sprintf("WS: error closing upgraded conn: %v", err))
		}
	}()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	requestForwarder := newRequestForwardingReader()
	request, err := http.NewRequestWithContext(
		r.Context(), r.Method, r.URL.String(), requestForwarder,
	)
	if err != nil {
		p.logger.Error().Msg(fmt.Sprintf("WS: error preparing request: %v", err))
		return
	}

	// Allow certain headers to be forwarded, either from source headers
	// or the special Sec-Websocket-Protocol header field.
	forwardHeaders(r.Header, request.Header)

	// Also allow the target request method to be overwritten, as all
	// WebSocket establishment calls MUST be GET requests.
	if m := r.URL.Query().Get(MethodOverrideParam); m != "" {
		request.Method = m
	}

	// Is this a call to a client-streaming RPC method?
	clientStreaming := false
	for _, pattern := range p.clientStreamingURIs {
		if pattern.MatchString(r.URL.Path) {
			clientStreaming = true
		}
	}

	responseForwarder := newResponseForwardingWriter()
	go func() {
		<-ctx.Done()
		responseForwarder.Close()
	}()

	go func() {
		defer cancelFn()
		p.backend.ServeHTTP(responseForwarder, request)
	}()

	// Read loop: Take messages from websocket and write to http request.
	go func() {
		defer cancelFn()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_, payload, err := conn.ReadMessage()
			if err != nil {
				if IsClosedConnError(err) {
					p.logger.Trace().Msg(fmt.Sprintf("WS: socket "+
						"closed: %v", err))
					return
				}
				p.logger.Error().Msg(fmt.Sprintf("error reading message: %v", err))
				return
			}
			_, err = requestForwarder.Write(payload)
			if err != nil {
				p.logger.Error().Msg(fmt.Sprintf("WS: error writing message to upstream http server: %v", err))
				return
			}
			_, _ = requestForwarder.Write([]byte{'\n'})

			// The grpc-gateway library uses a different request
			// reader depending on whether it is a client streaming
			// RPC or not. For a non-streaming request we need to
			// close with EOF to signal the request was completed.
			if !clientStreaming {
				requestForwarder.CloseWriter()
			}
		}
	}()

	// Ping write loop: Send a ping message regularly if ping/pong is
	// enabled.
	if p.pingPongEnabled() {
		// We'll send out our first ping in pingInterval. So the initial
		// deadline is that interval plus the time we allow for a
		// response to be sent.
		initialDeadline := time.Now().Add(p.pingInterval + p.pongWait)
		_ = conn.SetReadDeadline(initialDeadline)

		// Whenever a pong message comes in, we extend the deadline
		// until the next read is expected by the interval plus pong
		// wait time.
		conn.SetPongHandler(func(appData string) error {
			nextDeadline := time.Now().Add(
				p.pingInterval + p.pongWait,
			)
			_ = conn.SetReadDeadline(nextDeadline)
			return nil
		})
		go func() {
			ticker := time.NewTicker(p.pingInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					p.logger.Debug().Msg("WS: ping loop done")
					return

				case <-ticker.C:
					// Writing the ping shouldn't take any
					// longer than we'll wait for a response
					// in the first place.
					writeDeadline := time.Now().Add(
						p.pongWait,
					)
					_ = conn.SetWriteDeadline(writeDeadline)

					err := conn.WriteMessage(
						websocket.PingMessage, nil,
					)
					if err != nil {
						p.logger.Warn().Msg(fmt.Sprintf("WS: could not "+
							"send ping message: %v",
							err))
						return
					}
				}
			}
		}()
	}

	// Write loop: Take messages from the response forwarder and write them
	// to the WebSocket.
	for responseForwarder.Scan() {
		if len(responseForwarder.Bytes()) == 0 {
			p.logger.Error().Msg(fmt.Sprintf("WS: empty scan: %v",
				responseForwarder.Err()))

			continue
		}

		err = conn.WriteMessage(
			websocket.TextMessage, responseForwarder.Bytes(),
		)
		if err != nil {
			p.logger.Error().Msg(fmt.Sprintf("WS: error writing message: %v", err))
			return
		}
	}
	if err := responseForwarder.Err(); err != nil && !IsClosedConnError(err) {
		p.logger.Error().Msg(fmt.Sprintf("WS: scanner err: %v", err))
	}
}

// forwardHeaders forwards certain allowed header fields from the source request
// to the target request. Because browsers are limited in what header fields
// they can send on the WebSocket setup call, we also allow additional fields to
// be transported in the special Sec-Websocket-Protocol field.
func forwardHeaders(source, target http.Header) {
	// Forward allowed header fields directly.
	for header := range source {
		headerName := textproto.CanonicalMIMEHeaderKey(header)
		if forward, ok := defaultHeadersToForward[headerName]; ok && forward {
			target.Set(headerName, source.Get(header))
		}
	}

	// Browser aren't allowed to set custom header fields on WebSocket
	// requests. We need to allow them to submit the macaroon as a WS
	// protocol, which is the only allowed header. Set any "protocols" we
	// declare valid as header fields on the forwarded request.
	protocol := source.Get(HeaderWebSocketProtocol)
	for key := range defaultProtocolsToAllow {
		if strings.HasPrefix(protocol, key) {
			// The format is "<protocol name>+<value>". We know the
			// protocol string starts with the name so we only need
			// to set the value.
			values := strings.Split(
				protocol, WebSocketProtocolDelimiter,
			)
			target.Set(key, values[1])
		}
	}
}

// IsClosedConnError is a helper function that returns true if the given error
// is an error indicating we are using a closed connection.
func IsClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	if err == http.ErrServerClosed {
		return true
	}

	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}
	if strings.Contains(str, "closed pipe") {
		return true
	}
	if strings.Contains(str, "broken pipe") {
		return true
	}
	if strings.Contains(str, "connection reset by peer") {
		return true
	}
	return websocket.IsCloseError(
		err, websocket.CloseNormalClosure, websocket.CloseGoingAway,
	)
}

// newResponseForwardingWriter creates a new http.ResponseWriter that intercepts
// what's written to it and presents it through a bufio.Scanner interface.
func newResponseForwardingWriter() *responseForwardingWriter {
	r, w := io.Pipe()
	return &responseForwardingWriter{
		Writer:  w,
		Scanner: bufio.NewScanner(r),
		pipeR:   r,
		pipeW:   w,
		header:  http.Header{},
		closed:  make(chan bool, 1),
	}
}

// newRequestForwardingReader creates a new request forwarding pipe.
func newRequestForwardingReader() *requestForwardingReader {
	r, w := io.Pipe()
	return &requestForwardingReader{
		Reader: r,
		Writer: w,
		pipeR:  r,
		pipeW:  w,
	}
}

// CloseWriter closes the underlying pipe writer.
func (r *requestForwardingReader) CloseWriter() {
	_ = r.pipeW.CloseWithError(io.EOF)
}

// Write writes the given bytes to the internal pipe.
//
// NOTE: This is part of the http.ResponseWriter interface.
func (w *responseForwardingWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// Header returns the HTTP header fields intercepted so far.
//
// NOTE: This is part of the http.ResponseWriter interface.
func (w *responseForwardingWriter) Header() http.Header {
	return w.header
}

// WriteHeader indicates that the header part of the response is now finished
// and sets the response code.
//
// NOTE: This is part of the http.ResponseWriter interface.
func (w *responseForwardingWriter) WriteHeader(code int) {
	w.code = code
}

// CloseNotify returns a channel that indicates if a connection was closed.
//
// NOTE: This is part of the http.CloseNotifier interface.
func (w *responseForwardingWriter) CloseNotify() <-chan bool {
	return w.closed
}

// Flush empties all buffers. We implement this to indicate to our backend that
// we support flushing our content. There is no actual implementation because
// all writes happen immediately, there is no internal buffering.
//
// NOTE: This is part of the http.Flusher interface.
func (w *responseForwardingWriter) Flush() {}

func (w *responseForwardingWriter) Close() {
	_ = w.pipeR.CloseWithError(io.EOF)
	_ = w.pipeW.CloseWithError(io.EOF)
	w.closed <- true
}

```
We need to define a few new `Config` parameters, namely `RestPort`, `WSPingInterval` and `WSPongWait`. The ping/pong times are for maintaining the WebSocket connection.
```
...
type Config struct {
	DefaultLogDir  bool   `yaml:"DefaultLogDir"`
	LogFileDir     string `yaml:"LogFileDir"`
	ConsoleOutput  bool   `yaml:"ConsoleOutput"`
	GrpcPort       int64  `yaml:"GrpcPort"`
	RestPort       int64  `yaml:"RestPort"`
	WSPingInterval time.Duration
	WSPongWait     time.Duration
}

// all default values will be defined here
var (
	default_log_dir = func() string {
		home_dir, err := os.UserHomeDir() // this should be OS agnostic
		if err != nil {
			log.Fatal(err)
		}
		return home_dir + "/.bitswarmd"
	}
	default_grpc_port        int64 = 4567
	default_rest_port        int64 = 8080
	default_ws_ping_interval       = time.Second * 30
	default_ws_pong_wait           = time.Second * 5
	default_config                 = func() Config {
		return Config{
			DefaultLogDir:  true,
			LogFileDir:     default_log_dir(),
			ConsoleOutput:  true,
			GrpcPort:       default_grpc_port,
			RestPort:       default_rest_port,
			WSPingInterval: default_ws_ping_interval,
			WSPongWait:     default_ws_pong_wait,
		}
	}
)

// InitConfig returns an instantiated config struct either read from a yaml file or a default config
func InitConfig() (Config, error) {
	...
	config.WSPingInterval = default_ws_ping_interval
	config.WSPongWait = default_ws_pong_wait
	return config, nil
}

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
		case "RestPort":
			if f.Int() == 0 {
				change_field(f, default_rest_port)
			}
		}
	}
	return config
}
...
```
We will now create a couple of new functions in `auth/connection.go` to create our REST dial options and listener.
```
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

// GetRestOptions returns the necessary parameters to instantiate the REST gRPC proxy
func GetRestOptions() ([]grpc.DialOption, func(net.Addr) (net.Listener, error)) {
	restDialOpts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(
			maxMsgRecvSize,
		),
	}
	restListen := func(addr net.Addr) (net.Listener, error) {
		return net.Listen(parseNetwork(addr), addr.String())
	}
	return restDialOpts, restListen
}
```
We will also add a new method to the `RpcServer` struct in `bitswarm/rpcserver.go`
```
// RegisterWithRestProxy registers the RPC Server with the REST proxy
func (s *RpcServer) RegisterWithRestProxy(ctx context.Context, mux *proxy.ServeMux, restDialOpts []grpc.DialOption, restProxyDest string) error {
	err := swarmrpc.RegisterSwarmHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}
	return nil
}
```
Finally, we will modify `Main()` in `bitswarm/bitswarm.go` to start the REST proxy and add an additional helper function `startRestProxy()`.
```
func Main() {
    ...
    // Starting REST proxy
	restDialOpts, restListen := auth.GetRestOptions()
	stopProxy, err := startRestProxy(
		server.cfg, rpcServer, restDialOpts, restListen,
	)
	if err != nil {
		return err
	}
	defer stopProxy()
    
    // Listen for shutdown signals
	<-interceptor.ShutdownChannel()
	return nil
}
...
// startRestProxy starts the given REST proxy on the listeners found in the config.
func startRestProxy(cfg *Config, rpcServer *RpcServer, restDialOpts []grpc.DialOption, restListen func(net.Addr) (net.Listener, error)) (func(), error) {
	restProxyDestNet, err := utils.NormalizeAddresses([]string{fmt.Sprintf("localhost:%d", cfg.GrpcPort)}, strconv.FormatInt(cfg.GrpcPort, 10), net.ResolveTCPAddr)
	if err != nil {
		return nil, err
	}
	restProxyDest := restProxyDestNet[0].String()
	switch {
	case strings.Contains(restProxyDest, "0.0.0.0"):
		restProxyDest = strings.Replace(restProxyDest, "0.0.0.0", "127.0.0.1", 1)
	case strings.Contains(restProxyDest, "[::]"):
		restProxyDest = strings.Replace(restProxyDest, "[::]", "[::1]", 1)
	}
	var shutdownFuncs []func()
	shutdown := func() {
		for _, shutdownFn := range shutdownFuncs {
			shutdownFn()
		}
	}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	shutdownFuncs = append(shutdownFuncs, cancel)

	customMarshalerOption := proxy.WithMarshalerOption(
		proxy.MIMEWildcard, &proxy.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: true,
			},
		},
	)
	mux := proxy.NewServeMux(customMarshalerOption)

	err = rpcServer.RegisterWithRestProxy(
		ctx, mux, restDialOpts, restProxyDest,
	)
	if err != nil {
		return nil, err
	}
	// Wrap the default grpc-gateway handler with the WebSocket handler.
	restHandler := swarmrpc.NewWebSocketProxy(
		mux, rpcServer.logger, cfg.WSPingInterval, cfg.WSPongWait,
	)
	var wg sync.WaitGroup
	restEndpoints, err := utils.NormalizeAddresses([]string{fmt.Sprintf("localhost:%d", cfg.RestPort)}, strconv.FormatInt(cfg.RestPort, 10), net.ResolveTCPAddr)
	if err != nil {
		rpcServer.logger.Error().Msg(fmt.Sprintf("Unable to normalize address %s: %v", fmt.Sprintf("localhost:%d", cfg.RestPort), err))
	}
	restEndpoint := restEndpoints[0]
	lis, err := restListen(restEndpoint)
	if err != nil {
		rpcServer.logger.Error().Msg(fmt.Sprintf("gRPC REST proxy unable to listen on %s: %v", restEndpoint, err))
	}
	shutdownFuncs = append(shutdownFuncs, func() {
		err := lis.Close()
		if err != nil {
			rpcServer.logger.Error().Msg(fmt.Sprintf("Error closing listener: %v", err))
		}
	})
	wg.Add(1)
	go func() {
		rpcServer.logger.Info().Msg(fmt.Sprintf("gRPC REST proxy started and listening at %s", lis.Addr()))
		wg.Done()
		err := http.Serve(lis, restHandler)
		if err != nil && !swarmrpc.IsClosedConnError(err) {
			rpcServer.logger.Error().Msg(fmt.Sprintf("%v", err))
		}
	}()
	wg.Wait()
	return shutdown, nil
}
```
Finally if we compile and run, we can test our REST proxy with `curl`
```
$ curl -X GET http://localhost:8080/v1/test
{"msg":"This is a regular test"}$ curl -X GET http://localhost:8080/v1/stop
{}$
```
You'll notice that the REST responses are not properly formatted but they are working.

## Conclusion

This concludes the second part of the *LND Under the Hood* series. In the next and final part, we will learn how to integrate security and authentication for our API with TLS and macaroons. Hope you enjoyed reading.