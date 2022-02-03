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
	"context"
	"fmt"
	"io"
	"os"

	"github.com/TheRebelOfBabylon/weirwood/heartrpc"
	"github.com/TheRebelOfBabylon/weirwood/intercept"
	"github.com/urfave/cli"
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

// stopDaemon is the proxy command between heartcli and gRPC equivalent.
func stopDaemon(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getHeartTreeClient(ctx) //This command returns the proto generated SwarmClient instance
	defer cleanUp()

	_, err := client.StopDaemon(ctxc, &heartrpc.StopRequest{})
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
	client, cleanUp := getHeartTreeClient(ctx)
	defer cleanUp()
	testResp, err := client.TestCommand(ctxc, &heartrpc.TestRequest{})
	if err != nil {
		return err
	}
	printRespJSON(testResp)
	return nil
}

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
	client, cleanUp := getHeartTreeClient(ctx)
	defer cleanUp()
	stream, err := client.AdminTest(ctxc, &heartrpc.AdminTestRequest{})
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

var addNodeCommand = cli.Command{
	Name:      "addnode",
	Usage:     "Adds the user inputted onion address to the daemon database",
	ArgsUsage: "onion-addr",
	Description: `
	There is one required argument for this command, the onion address of the seeder with format validonionaddreess.onion:port`,
	Action: addNode,
}

// addNode implements the gRPC AddSeeder command
func addNode(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "addnode")
	}
	ctxc := getContext()
	client, cleanUp := getHeartTreeClient(ctx)
	defer cleanUp()
	nodeAddr := ctx.Args().First()
	resp, err := client.AddNode(ctxc, &heartrpc.AddNodeRequest{
		OnionAddr: nodeAddr,
	})
	if err != nil {
		return err
	}
	printRespJSON(resp)
	return nil
}

var listNodesCommand = cli.Command{
	Name:  "listnodes",
	Usage: "Prints a list of all nodes stored in the database.",
	Description: `
	Requires no arguments. It returns a list of all previously added nodes from the database.`,
	Action: listNodes,
}

// listNodes returns a list of all currently stored node addresses in the database
func listNodes(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getHeartTreeClient(ctx)
	defer cleanUp()
	stream, err := client.ListNodes(ctxc, &heartrpc.ListNodesRequest{})
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

var deleteNodeCommand = cli.Command{
	Name:  "deletenode",
	Usage: "Deletes the node corresponding to the user inputted onion address.",
	Description: `
	A single argument is required, the onion address of the node we wish to delete from the database`,
	Action: deleteNode,
}

// deleteNode removes a node from the database based on user inputted onion address
func deleteNode(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return cli.ShowCommandHelp(ctx, "deletenode")
	}
	ctxc := getContext()
	client, cleanUp := getHeartTreeClient(ctx)
	defer cleanUp()
	nodeAddr := ctx.Args().First()
	resp, err := client.DeleteNode(ctxc, &heartrpc.DeleteNodeRequest{
		OnionAddr: nodeAddr,
	})
	if err != nil {
		return err
	}
	printRespJSON(resp)
	return nil
}
