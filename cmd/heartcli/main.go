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
	"fmt"
	"os"
	"path/filepath"

	"github.com/TheRebelOfBabylon/weirwood/auth"
	"github.com/TheRebelOfBabylon/weirwood/heartrpc"
	"github.com/TheRebelOfBabylon/weirwood/utils"
	"github.com/urfave/cli"
)

var (
	defaultRPCAddr               = "localhost"
	defaultRPCPort               = "4567"
	defaultTLSCertFilename       = "tls.cert"
	defaultWeirwoodDir           = utils.AppDataDir("weirwood", false)
	defaultTLSCertPath           = filepath.Join(defaultWeirwoodDir, defaultTLSCertFilename)
	defaultMacaroonTimeout int64 = 60
	defaultAdminMacName          = "admin.macaroon"
	defaultMacPath               = filepath.Join(defaultWeirwoodDir, defaultAdminMacName)
)

type Args struct {
	RPCAddr      string
	RPCPort      string
	TLSCertPath  string
	AdminMacPath string
}

// fatal exits the process and prints out error information
func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[heartcli] %v\n", err)
	os.Exit(1)
}

// getHeartTreeClient returns the HeartTreeClient instance from the heartrpc package as well as a cleanup function
func getHeartTreeClient(ctx *cli.Context) (heartrpc.HeartTreeClient, func()) {
	args := extractArgs(ctx)
	conn, err := auth.GetClientConn(args.RPCAddr, args.RPCPort, args.TLSCertPath, args.AdminMacPath, false, defaultMacaroonTimeout)
	if err != nil {
		fatal(err)
	}
	cleanUp := func() {
		conn.Close()
	}
	return heartrpc.NewHeartTreeClient(conn), cleanUp
}

// getUnlockerClient returns the UnlockerClient instance from the heartrpc package as well as a cleanup function
func getUnlockerClient(ctx *cli.Context) (heartrpc.UnlockerClient, func()) {
	args := extractArgs(ctx)
	conn, err := auth.GetClientConn(args.RPCAddr, args.RPCPort, args.TLSCertPath, args.AdminMacPath, true, defaultMacaroonTimeout)
	if err != nil {
		fatal(err)
	}
	cleanUp := func() {
		conn.Close()
	}
	return heartrpc.NewUnlockerClient(conn), cleanUp
}

// extractArgs extracts the arguments inputted to the heartcli command
func extractArgs(ctx *cli.Context) *Args {
	return &Args{
		RPCAddr:      ctx.GlobalString("rpc_addr"),
		RPCPort:      ctx.GlobalString("rpc_port"),
		TLSCertPath:  ctx.GlobalString("tlscertpath"),
		AdminMacPath: ctx.GlobalString("macaroonpath"),
	}
}

// main is the entrypoint for heartcli
func main() {
	app := cli.NewApp()
	app.Name = "heartcli"
	app.Usage = "Command Line tool for the Bitswarm Daemon (weirwood)"
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
			Usage:     "The path to weirwood's TLS certificate.",
			TakesFile: true,
		},
		cli.StringFlag{
			Name:      "macaroonpath",
			Value:     defaultMacPath,
			Usage:     "The path to weirwood's macaroons.",
			TakesFile: true,
		},
	}
	app.Commands = []cli.Command{
		stopCommand,
		testCommand,
		setPassword,
		unlockCommand,
		changePassword,
		adminTestCommand,
		addNodeCommand,
		listNodesCommand,
		deleteNodeCommand,
	}
	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
