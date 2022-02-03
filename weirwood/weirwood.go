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

package weirwood

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/TheRebelOfBabylon/weirwood/cert"
	"github.com/TheRebelOfBabylon/weirwood/heartrpc"
	"github.com/TheRebelOfBabylon/weirwood/intercept"
	"github.com/TheRebelOfBabylon/weirwood/kvdb"
	"github.com/TheRebelOfBabylon/weirwood/macaroons"
	"github.com/TheRebelOfBabylon/weirwood/unlocker"
	"github.com/TheRebelOfBabylon/weirwood/utils"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

// Main is the true entry point for weirwoodd. It's called in a nested manner for proper defer execution
func Main(interceptor *intercept.Interceptor, server *Server) error {
	var restServices []utils.ElligibleRestService
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Starting main server
	err := server.Start()
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not start daemon: %v", err))
		return err
	}
	defer server.Stop()

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
	rpcServer, err := NewRpcServer(interceptor, server.cfg, NewSubLogger(server.logger, "RPCS"))
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize RPC server: %v", err))
		return err
	}
	restServices = append(restServices, rpcServer)
	server.logger.Info().Msg("RPC Server Initialized.")

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

	// Starting kvdb
	server.logger.Info().Msg("Opening database...")
	db, err := kvdb.NewDB(server.cfg.DBPath)
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize Macaroon DB: %v", err))
		return err
	}
	server.logger.Info().Msg("Database successfully opened.")
	defer db.Close()

	// Instantiate Unlocker Service and register with gRPC server
	server.logger.Info().Msg("Initializing unlocker service...")
	unlockerService, err := unlocker.NewUnlockerService(db, []string{server.cfg.AdminMacPath, server.cfg.TestMacPath})
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not initialize unlocker service: %v", err))
		return err
	}
	defer unlockerService.Stop()
	unlockerService.RegisterWithGrpcServer(grpc_server)
	restServices = append(restServices, unlockerService)
	server.logger.Info().Msg("Unlocker service initialized.")

	//Starting RPC and gRPC Servers
	err = rpcServer.Start()
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not start RPC server: %v", err))
		return err
	}
	defer rpcServer.Stop()

	// Adding db to rpcServer
	err = rpcServer.AddDb(db)
	if err != nil {
		return err
	}

	// start gRPC listening
	err = startGrpcListen(grpc_server, rpcServer.Listener)
	if err != nil {
		rpcServer.logger.Fatal().Msg(fmt.Sprintf("Could not start gRPC listen on %v:%v", rpcServer.Listener.Addr(), err))
		return err
	}
	rpcServer.logger.Info().Msg(fmt.Sprintf("gRPC listening on %v", rpcServer.Listener.Addr()))

	// Starting REST proxy
	stopProxy, err := startRestProxy(
		server.cfg, rpcServer, restDialOpts, restListen, restServices,
	)
	if err != nil {
		return err
	}
	defer stopProxy()

	// Wait for password
	server.logger.Info().Msg("Waiting for password. Use `heartcli setpassword` to set a password for the first time, " +
		"`heartcli unlock` to unlock the daemon with an existing password, or `heartcli changepassword` to change the " +
		"existing password and unlock the daemon.",
	)
	resp, err := waitForPassword(unlockerService, interceptor.ShutdownChannel())
	if err != nil {
		server.logger.Error().Msg(fmt.Sprintf("Error while awaiting password: %v", err))
	}

	// Instantiating Macaroon Service
	server.logger.Info().Msg("Initiating macaroon service...")
	macaroonService, err := macaroons.InitService(*db, "weirwood", resp.StatelessInit)
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
		err = genMacaroons(
			ctx, macaroonService, utils.AppDataDir("weirwood", false)+"/write.macaroon", writePermissions, true, 120,
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

	// Listen for shutdown signals
	<-interceptor.ShutdownChannel()
	return nil
}

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

// startRestProxy starts the given REST proxy on the listeners found in the config.
func startRestProxy(
	cfg *Config,
	rpcServer *RpcServer,
	restDialOpts []grpc.DialOption,
	restListen func(net.Addr) (net.Listener, error),
	restServices []utils.ElligibleRestService,
) (func(), error) {
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

	// Go through the list of elligible rest services and register them with the Rest Proxy
	for _, s := range restServices {
		err = s.RegisterWithRestProxy(
			ctx, mux, restDialOpts, restProxyDest,
		)
		if err != nil {
			return nil, err
		}
	}
	// Wrap the default grpc-gateway handler with the WebSocket handler.
	restHandler := heartrpc.NewWebSocketProxy(
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
		if err != nil && !heartrpc.IsClosedConnError(err) {
			rpcServer.logger.Error().Msg(fmt.Sprintf("%v", err))
		}
	}()
	wg.Wait()
	return shutdown, nil
}

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
