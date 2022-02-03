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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/TheRebelOfBabylon/weirwood/heartrpc"
	"github.com/TheRebelOfBabylon/weirwood/intercept"
	"github.com/TheRebelOfBabylon/weirwood/kvdb"
	"github.com/TheRebelOfBabylon/weirwood/macaroons"
	"github.com/TheRebelOfBabylon/weirwood/utils"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	readPermissions = []bakery.Op{
		{
			Entity: "heart",
			Action: "read",
		},
		{
			Entity: "macaroon",
			Action: "read",
		},
		{
			Entity: "user",
			Action: "read",
		},
	}
	writePermissions = []bakery.Op{
		{
			Entity: "heart",
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
		{
			Entity: "user",
			Action: "write",
		},
	}
	validActions  = []string{"read", "write", "generate"}
	validEntities = []string{
		"heart", "macaroon", "user",
		macaroons.PermissionEntityCustomURI,
	}
	nodeBucketName = []byte("nodeAddrs")
)

// MainRPCServerPermissions returns a mapping of the main RPC server calls to
// the permissions they require.
func MainRPCServerPermissions() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		"/heartrpc.HeartTree/StopDaemon": {{
			Entity: "user",
			Action: "write",
		}},
		"/heartrpc.HeartTree/TestCommand": {{
			Entity: "heart",
			Action: "read",
		}},
		"/heartrpc.HeartTree/AdminTest": {{
			Entity: "heart",
			Action: "read",
		}},
		"/heartrpc.HeartTree/AddNode": {{
			Entity: "heart",
			Action: "write",
		}},
		"/heartrpc.HeartTree/ListNodes": {{
			Entity: "heart",
			Action: "read",
		}},
		"/heartrpc.HeartTree/DeleteNode": {{
			Entity: "heart",
			Action: "write",
		}},
	}
}

// RpcServer is a child of the heartrpc.UnimplementedHeartTreeServer struct. Meant to host all related attributes to the rpcserver
type RpcServer struct {
	Running int32 // used atomically
	heartrpc.UnimplementedHeartTreeServer
	interceptor *intercept.Interceptor
	cfg         *Config
	logger      *zerolog.Logger
	Listener    net.Listener
	db          *kvdb.DB
}

// This tests whether *RpcServer implements the ElligibleRestService Interface
var _ utils.ElligibleRestService = (*RpcServer)(nil)

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
	r.logger.Info().Msg("RPC server started")
	return nil
}

// Stop stops the server. Returns an error if any issues occur
func (r *RpcServer) Stop() error {
	r.logger.Info().Msg("Stopping RPC server...")
	if ok := atomic.CompareAndSwapInt32(&r.Running, 1, 0); !ok {
		return fmt.Errorf("Could not stop RPC server: server already stopped.")
	}
	r.logger.Info().Msg("RPC server stopped")
	return nil
}

// RegisterWithGrpcServer registers the rpcServer with the root gRPC server.
func (r *RpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	heartrpc.RegisterHeartTreeServer(grpcServer, r)
	return nil
}

// RegisterWithRestProxy registers the RPC Server with the REST proxy
func (r *RpcServer) RegisterWithRestProxy(ctx context.Context, mux *proxy.ServeMux, restDialOpts []grpc.DialOption, restProxyDest string) error {
	err := heartrpc.RegisterHeartTreeHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}
	return nil
}

// AddDb adds the db to the RpcServer for use with other RPC commands
func (r *RpcServer) AddDb(db *kvdb.DB) error {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(nodeBucketName)
		return err
	}); err != nil {
		r.logger.Error().Msg(fmt.Sprintf("Could not add db to RPC server: %v", err))
		return err
	}
	r.db = db
	return nil
}

// StopDaemon will send a shutdown request to the interrupt handler, triggering a graceful shutdown
func (r *RpcServer) StopDaemon(_ context.Context, _ *heartrpc.StopRequest) (*heartrpc.StopResponse, error) {
	r.interceptor.RequestShutdown()
	return &heartrpc.StopResponse{}, nil
}

// TestCommand will return a string for any macaroon
func (r *RpcServer) TestCommand(_ context.Context, _ *heartrpc.TestRequest) (*heartrpc.TestResponse, error) {
	return &heartrpc.TestResponse{Msg: "This is a regular test"}, nil
}

// AdminTest will return a stream of responses provided a specific macaroon
func (r *RpcServer) AdminTest(_ *heartrpc.AdminTestRequest, updateStream heartrpc.HeartTree_AdminTestServer) error {
	for i := 0; i < 10; i++ {
		select {
		case <-updateStream.Context().Done():
			if errors.Is(updateStream.Context().Err(), context.Canceled) {
				return nil
			}
			return updateStream.Context().Err()
		default:
			msg := "Test string %v"
			object := &heartrpc.AdminTestResponse{
				Msg: fmt.Sprintf(msg, i),
			}
			if err := updateStream.Send(object); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetListOfNodes returns the current list of nodes
func (r *RpcServer) GetListOfNodes() ([]string, error) {
	r.db.Mutex.RLock()
	defer r.db.Mutex.RUnlock()
	listOfNodes := []string{}
	err := r.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(nodeBucketName)
		if bucket == nil {
			return fmt.Errorf("Seeder bucket not fond")
		}
		bucket.ForEach(func(k, v []byte) error {
			listOfNodes = append(listOfNodes, string(v[:]))
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return listOfNodes, err
}

// itob returns an 8-byte big endian representation of v
func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// addNode takes an onion address string and stores it in the db if it isn't already there
func (r *RpcServer) addNode(onion_addr string) error {
	r.db.Mutex.Lock()
	defer r.db.Mutex.Unlock()
	return r.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(nodeBucketName) // get the seeder bucket
		if bucket == nil {
			return fmt.Errorf("Seeder bucket not found")
		}
		// First let's check if the onion address is already in the database
		err := bucket.ForEach(func(k, v []byte) error {
			if bytes.Compare(v, []byte(onion_addr)) == 0 {
				return fmt.Errorf("Onion address already saved in database")
			}
			return nil
		})
		if err != nil {
			return err
		}
		id, _ := bucket.NextSequence()
		return bucket.Put(itob(id), []byte(onion_addr))
	})
}

// AddNode takes in a AddNodeRequest, stores the onion_addr parameters of the request in the db and sends a response upon success.
func (r *RpcServer) AddNode(_ context.Context, req *heartrpc.AddNodeRequest) (*heartrpc.AddNodeResponse, error) {
	// first let's remove the port from the address and validate it's an actual port
	host, portStr, err := net.SplitHostPort(req.OnionAddr)
	if err != nil {
		return nil, fmt.Errorf("Could not add %v to database: %v", req.OnionAddr, err)
	}
	_, err = strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("Could not add %v to database: %v", req.OnionAddr, err)
	}
	// second let's validate the onion address
	if ok := tor.IsOnionHost(host); !ok {
		return nil, fmt.Errorf("Could not add %v to database: invalid address", req.OnionAddr)
	}
	err = r.addNode(req.OnionAddr)
	if err != nil {
		return nil, fmt.Errorf("Could not add %v to database: %v", req.OnionAddr, err)
	}
	return &heartrpc.AddNodeResponse{}, nil
}

// ListNodes will return a complete list of all nodes stored in the db
func (r *RpcServer) ListNodes(_ *heartrpc.ListNodesRequest, updateStream heartrpc.HeartTree_ListNodesServer) error {
	nodes, err := r.GetListOfNodes()
	if err != nil {
		return fmt.Errorf("Could not get list of seeders: %v", err)
	}
	for _, node := range nodes {
		select {
		case <-updateStream.Context().Done():
			if errors.Is(updateStream.Context().Err(), context.Canceled) {
				return nil
			}
			return updateStream.Context().Err()
		default:
			s := &heartrpc.GetInfoResponse{
				OnionAddr: node,
			}
			if err := updateStream.Send(s); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteNode deletes the noder with the given onion address from the list of nodes in the database
func (r *RpcServer) deleteNode(onion_addr string) error {
	r.db.Mutex.Lock()
	defer r.db.Mutex.Unlock()
	return r.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(nodeBucketName) // get the seeder bucket
		if bucket == nil {
			return fmt.Errorf("Seeder bucket not found")
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if bytes.Compare(v, []byte(onion_addr)) == 0 {
				err := bucket.Delete(k)
				if err != nil {
					tx.Rollback()
					return err
				}
			}
		}
		return nil
	})
}

// DeleteNode deletes the node with the given onion address from the list of nodes in the database
func (r *RpcServer) DeleteNode(_ context.Context, req *heartrpc.DeleteNodeRequest) (*heartrpc.DeleteNodeResponse, error) {
	err := r.deleteNode(req.OnionAddr)
	if err != nil {
		return nil, fmt.Errorf("Could not delete %v: %v", req.OnionAddr, err)
	}
	return &heartrpc.DeleteNodeResponse{}, nil
}
