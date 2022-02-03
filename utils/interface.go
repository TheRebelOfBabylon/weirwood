package utils

import (
	"context"

	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

// ElligibleRestService is an interface made to conveniently group all services that can be registered with the REST proxy
type ElligibleRestService interface {
	RegisterWithRestProxy(context.Context, *proxy.ServeMux, []grpc.DialOption, string) error
}
