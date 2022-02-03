# weirwood

Repository for the Weirwood Daemon. Just like the heart tree in *A Song of Ice and Fire* the weirwood daemon is a place to store the knowledge of the world. Find peers who are running weirwood, pay them to store your files. This is an attempt at a decentralized cloud storage. This is not torrenting.

Planned features include:
- Default useage of file encryption and Tor for maximum privacy and protection
- Integration with Bitcoin Lightning Payments
- Integration with Aperture, a HTTP 402 Lightning Service Authentication Token Reverse Proxy

# Installation

weirwood runs on Go 1.17

On Linux:

```
$ wget https://golang.org/dl/go1.17.1.linux-amd64.tar.gz
$ sha256sum go1.17.1.linux-amd64.tar.gz | awk -F " " '{ print $1 }'
dab7d9c34361dc21ec237d584590d72500652e7c909bf082758fb63064fca0ef
```
`dab7d9c34361dc21ec237d584590d72500652e7c909bf082758fb63064fca0ef` is what you should see to verify the SHA256 checksum
```
$ sudo tar -C /usr/local -xzf go1.17.1.linux-amd64.tar.gz
```
Now modify your `.bashrc` or `.bash_profile` and add the following lines:
```
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/Path/To/Your/Working/Directory
export PATH=$PATH:$GOPATH/bin
```
If you type `$ go version` you should see `go1.17 linux/amd64`

## Installing weirwood from source

In your working directory (which is your `GOPATH`), create a `/src/github.com/TheRebelOfBabylon` directory
```
$ mkdir src/github.com/TheRebelOfBabylon
$ cd src/github.com/TheRebelOfBabylon
```
Then clone the repository
```
$ git clone git@github.com:TheRebelOfBabylon/weirwood.git
$ cd weirwood
```

## Installing Protoc

In order to compile protos in Go, you need `protoc`.

On Linux:

```
$uname -m
x86_64
```
To check your OS architecture. Once you find that, go to https://github.com/protocolbuffers/protobuf/releases and find the releases that matches your OS and architecture. In your $HOME directory:
```
$ curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protoc-3.17.3-linux-x86_64.zip
$ unzip protoc-3.17.3-linux-x86_64.zip -d $HOME/.local
```
Add the following line to `.bashrc` or `.bash_profile`
```
export PATH=$PATH:$HOME/.local/bin
```
Then
```
$ source .bashrc            #or source .bash_profile
$ protoc --version
libprotoc 3.17.3
```
## Installing REST to gRPC Proxy Dependencies

For REST proxy and OpenAPI commands to work, some dependencies are needed and are installed as follows:
```
$ go get github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
     github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
     google.golang.org/protobuf/cmd/protoc-gen-go \
     google.golang.org/grpc/cmd/protoc-gen-go-grpc
```

# Testing

[This blog post](https://blog.alexellis.io/golang-writing-unit-tests/) covers how Go handles unit tests natively. A strategy for integration testing will be devised at a later time. 

To perform unit tests, run the following command from the projects root directory:
```
$ go test -v ./...
```

# Compiling Binaries

## Linux
A Makefile has been created to simplify the process. It's important that this project be in the expected location (i.e. $GOPATH/src/github.com/TheRebelOfBabylon/weirwood). Simply run the following from the root directory to compile binaries
```
$ make install
```

# Adding New Commands and Compiling Protos
In the `heartrpc` directory are the proto files for the RPC server. When new commands are created, the protos must be recompiled:
```
$ protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative heart.proto
```
The REST reverse proxy and OpenAPI file are compiled as follows:
```
$ protoc --grpc-gateway_out=. --grpc-gateway_opt=logtostderr=true --grpc-gateway_opt=paths=source_relative --grpc-gateway_opt=grpc_api_configuration=heart.yaml heart.proto
$ protoc --openapiv2_out=. --openapiv2_opt=logtostderr=true --openapiv2_opt=grpc_api_configuration=heart.yaml --openapiv2_opt=json_names_for_fields=false heart.proto
```
or use `gen_protos.sh`
```
$ ./gen_protos.sh -y heart.yaml -p heart.proto
```

Write the command and define its permissionsin the `weirwood/rpcserver.go` file. For swarmcli access, write a proxy in `cmd/heartcli/commands.go` and add it to the list of commands in `cmd/heartcli/main.go`