// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.1
// source: heart.proto

package heartrpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// HeartTreeClient is the client API for HeartTree service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HeartTreeClient interface {
	// heartcli: `stop`
	//StopDaemon will send a shutdown request to the interrupt handler, triggering
	//a graceful shutdown of the daemon.
	StopDaemon(ctx context.Context, in *StopRequest, opts ...grpc.CallOption) (*StopResponse, error)
	// heartcli: `test`
	//TestCommand will send a string response regardless if a macaroon is provided or not.
	TestCommand(ctx context.Context, in *TestRequest, opts ...grpc.CallOption) (*TestResponse, error)
	// heartcli: `admintest`
	//AdminTest will send a string response only if a macaroon is provided.
	AdminTest(ctx context.Context, in *AdminTestRequest, opts ...grpc.CallOption) (HeartTree_AdminTestClient, error)
	// heartcli: `addnode`
	//AddNode takes the user inputted onion address with format validonionaddreess.onion:port of another node and adds it to a list of known nodes.
	AddNode(ctx context.Context, in *AddNodeRequest, opts ...grpc.CallOption) (*AddNodeResponse, error)
	// heartcli: `deletenode`
	//DeleteNode takes the user inputted onion address of a node and removes it from the list of known nodes.
	DeleteNode(ctx context.Context, in *DeleteNodeRequest, opts ...grpc.CallOption) (*DeleteNodeResponse, error)
	// heartcli: `listnodes`
	//ListNodes returns a list of all nodes in the list
	ListNodes(ctx context.Context, in *ListNodesRequest, opts ...grpc.CallOption) (HeartTree_ListNodesClient, error)
	// heartcli: `getinfo`
	//GetInfo returns general information about the given node including it's capabilities, prices, etc.
	//If no address is given, it is assumed to be the localhost node
	GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error)
	//
	//SeedFile takes a SeedFileRequest including a filename, filesize and upon payment, returns TCP upload information. Upon successful download, returns a magnet link
	SeedFile(ctx context.Context, in *SeedFileRequest, opts ...grpc.CallOption) (HeartTree_SeedFileClient, error)
}

type heartTreeClient struct {
	cc grpc.ClientConnInterface
}

func NewHeartTreeClient(cc grpc.ClientConnInterface) HeartTreeClient {
	return &heartTreeClient{cc}
}

func (c *heartTreeClient) StopDaemon(ctx context.Context, in *StopRequest, opts ...grpc.CallOption) (*StopResponse, error) {
	out := new(StopResponse)
	err := c.cc.Invoke(ctx, "/heartrpc.HeartTree/StopDaemon", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heartTreeClient) TestCommand(ctx context.Context, in *TestRequest, opts ...grpc.CallOption) (*TestResponse, error) {
	out := new(TestResponse)
	err := c.cc.Invoke(ctx, "/heartrpc.HeartTree/TestCommand", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heartTreeClient) AdminTest(ctx context.Context, in *AdminTestRequest, opts ...grpc.CallOption) (HeartTree_AdminTestClient, error) {
	stream, err := c.cc.NewStream(ctx, &HeartTree_ServiceDesc.Streams[0], "/heartrpc.HeartTree/AdminTest", opts...)
	if err != nil {
		return nil, err
	}
	x := &heartTreeAdminTestClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type HeartTree_AdminTestClient interface {
	Recv() (*AdminTestResponse, error)
	grpc.ClientStream
}

type heartTreeAdminTestClient struct {
	grpc.ClientStream
}

func (x *heartTreeAdminTestClient) Recv() (*AdminTestResponse, error) {
	m := new(AdminTestResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *heartTreeClient) AddNode(ctx context.Context, in *AddNodeRequest, opts ...grpc.CallOption) (*AddNodeResponse, error) {
	out := new(AddNodeResponse)
	err := c.cc.Invoke(ctx, "/heartrpc.HeartTree/AddNode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heartTreeClient) DeleteNode(ctx context.Context, in *DeleteNodeRequest, opts ...grpc.CallOption) (*DeleteNodeResponse, error) {
	out := new(DeleteNodeResponse)
	err := c.cc.Invoke(ctx, "/heartrpc.HeartTree/DeleteNode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heartTreeClient) ListNodes(ctx context.Context, in *ListNodesRequest, opts ...grpc.CallOption) (HeartTree_ListNodesClient, error) {
	stream, err := c.cc.NewStream(ctx, &HeartTree_ServiceDesc.Streams[1], "/heartrpc.HeartTree/ListNodes", opts...)
	if err != nil {
		return nil, err
	}
	x := &heartTreeListNodesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type HeartTree_ListNodesClient interface {
	Recv() (*GetInfoResponse, error)
	grpc.ClientStream
}

type heartTreeListNodesClient struct {
	grpc.ClientStream
}

func (x *heartTreeListNodesClient) Recv() (*GetInfoResponse, error) {
	m := new(GetInfoResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *heartTreeClient) GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error) {
	out := new(GetInfoResponse)
	err := c.cc.Invoke(ctx, "/heartrpc.HeartTree/GetInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heartTreeClient) SeedFile(ctx context.Context, in *SeedFileRequest, opts ...grpc.CallOption) (HeartTree_SeedFileClient, error) {
	stream, err := c.cc.NewStream(ctx, &HeartTree_ServiceDesc.Streams[2], "/heartrpc.HeartTree/SeedFile", opts...)
	if err != nil {
		return nil, err
	}
	x := &heartTreeSeedFileClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type HeartTree_SeedFileClient interface {
	Recv() (*SeedFileResponse, error)
	grpc.ClientStream
}

type heartTreeSeedFileClient struct {
	grpc.ClientStream
}

func (x *heartTreeSeedFileClient) Recv() (*SeedFileResponse, error) {
	m := new(SeedFileResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// HeartTreeServer is the server API for HeartTree service.
// All implementations must embed UnimplementedHeartTreeServer
// for forward compatibility
type HeartTreeServer interface {
	// heartcli: `stop`
	//StopDaemon will send a shutdown request to the interrupt handler, triggering
	//a graceful shutdown of the daemon.
	StopDaemon(context.Context, *StopRequest) (*StopResponse, error)
	// heartcli: `test`
	//TestCommand will send a string response regardless if a macaroon is provided or not.
	TestCommand(context.Context, *TestRequest) (*TestResponse, error)
	// heartcli: `admintest`
	//AdminTest will send a string response only if a macaroon is provided.
	AdminTest(*AdminTestRequest, HeartTree_AdminTestServer) error
	// heartcli: `addnode`
	//AddNode takes the user inputted onion address with format validonionaddreess.onion:port of another node and adds it to a list of known nodes.
	AddNode(context.Context, *AddNodeRequest) (*AddNodeResponse, error)
	// heartcli: `deletenode`
	//DeleteNode takes the user inputted onion address of a node and removes it from the list of known nodes.
	DeleteNode(context.Context, *DeleteNodeRequest) (*DeleteNodeResponse, error)
	// heartcli: `listnodes`
	//ListNodes returns a list of all nodes in the list
	ListNodes(*ListNodesRequest, HeartTree_ListNodesServer) error
	// heartcli: `getinfo`
	//GetInfo returns general information about the given node including it's capabilities, prices, etc.
	//If no address is given, it is assumed to be the localhost node
	GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error)
	//
	//SeedFile takes a SeedFileRequest including a filename, filesize and upon payment, returns TCP upload information. Upon successful download, returns a magnet link
	SeedFile(*SeedFileRequest, HeartTree_SeedFileServer) error
	mustEmbedUnimplementedHeartTreeServer()
}

// UnimplementedHeartTreeServer must be embedded to have forward compatible implementations.
type UnimplementedHeartTreeServer struct {
}

func (UnimplementedHeartTreeServer) StopDaemon(context.Context, *StopRequest) (*StopResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopDaemon not implemented")
}
func (UnimplementedHeartTreeServer) TestCommand(context.Context, *TestRequest) (*TestResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestCommand not implemented")
}
func (UnimplementedHeartTreeServer) AdminTest(*AdminTestRequest, HeartTree_AdminTestServer) error {
	return status.Errorf(codes.Unimplemented, "method AdminTest not implemented")
}
func (UnimplementedHeartTreeServer) AddNode(context.Context, *AddNodeRequest) (*AddNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddNode not implemented")
}
func (UnimplementedHeartTreeServer) DeleteNode(context.Context, *DeleteNodeRequest) (*DeleteNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteNode not implemented")
}
func (UnimplementedHeartTreeServer) ListNodes(*ListNodesRequest, HeartTree_ListNodesServer) error {
	return status.Errorf(codes.Unimplemented, "method ListNodes not implemented")
}
func (UnimplementedHeartTreeServer) GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetInfo not implemented")
}
func (UnimplementedHeartTreeServer) SeedFile(*SeedFileRequest, HeartTree_SeedFileServer) error {
	return status.Errorf(codes.Unimplemented, "method SeedFile not implemented")
}
func (UnimplementedHeartTreeServer) mustEmbedUnimplementedHeartTreeServer() {}

// UnsafeHeartTreeServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HeartTreeServer will
// result in compilation errors.
type UnsafeHeartTreeServer interface {
	mustEmbedUnimplementedHeartTreeServer()
}

func RegisterHeartTreeServer(s grpc.ServiceRegistrar, srv HeartTreeServer) {
	s.RegisterService(&HeartTree_ServiceDesc, srv)
}

func _HeartTree_StopDaemon_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeartTreeServer).StopDaemon(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/heartrpc.HeartTree/StopDaemon",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeartTreeServer).StopDaemon(ctx, req.(*StopRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _HeartTree_TestCommand_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeartTreeServer).TestCommand(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/heartrpc.HeartTree/TestCommand",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeartTreeServer).TestCommand(ctx, req.(*TestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _HeartTree_AdminTest_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(AdminTestRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HeartTreeServer).AdminTest(m, &heartTreeAdminTestServer{stream})
}

type HeartTree_AdminTestServer interface {
	Send(*AdminTestResponse) error
	grpc.ServerStream
}

type heartTreeAdminTestServer struct {
	grpc.ServerStream
}

func (x *heartTreeAdminTestServer) Send(m *AdminTestResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _HeartTree_AddNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeartTreeServer).AddNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/heartrpc.HeartTree/AddNode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeartTreeServer).AddNode(ctx, req.(*AddNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _HeartTree_DeleteNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeartTreeServer).DeleteNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/heartrpc.HeartTree/DeleteNode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeartTreeServer).DeleteNode(ctx, req.(*DeleteNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _HeartTree_ListNodes_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ListNodesRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HeartTreeServer).ListNodes(m, &heartTreeListNodesServer{stream})
}

type HeartTree_ListNodesServer interface {
	Send(*GetInfoResponse) error
	grpc.ServerStream
}

type heartTreeListNodesServer struct {
	grpc.ServerStream
}

func (x *heartTreeListNodesServer) Send(m *GetInfoResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _HeartTree_GetInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeartTreeServer).GetInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/heartrpc.HeartTree/GetInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeartTreeServer).GetInfo(ctx, req.(*GetInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _HeartTree_SeedFile_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SeedFileRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HeartTreeServer).SeedFile(m, &heartTreeSeedFileServer{stream})
}

type HeartTree_SeedFileServer interface {
	Send(*SeedFileResponse) error
	grpc.ServerStream
}

type heartTreeSeedFileServer struct {
	grpc.ServerStream
}

func (x *heartTreeSeedFileServer) Send(m *SeedFileResponse) error {
	return x.ServerStream.SendMsg(m)
}

// HeartTree_ServiceDesc is the grpc.ServiceDesc for HeartTree service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var HeartTree_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "heartrpc.HeartTree",
	HandlerType: (*HeartTreeServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StopDaemon",
			Handler:    _HeartTree_StopDaemon_Handler,
		},
		{
			MethodName: "TestCommand",
			Handler:    _HeartTree_TestCommand_Handler,
		},
		{
			MethodName: "AddNode",
			Handler:    _HeartTree_AddNode_Handler,
		},
		{
			MethodName: "DeleteNode",
			Handler:    _HeartTree_DeleteNode_Handler,
		},
		{
			MethodName: "GetInfo",
			Handler:    _HeartTree_GetInfo_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "AdminTest",
			Handler:       _HeartTree_AdminTest_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "ListNodes",
			Handler:       _HeartTree_ListNodes_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "SeedFile",
			Handler:       _HeartTree_SeedFile_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "heart.proto",
}
