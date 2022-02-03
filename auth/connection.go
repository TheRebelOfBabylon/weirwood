package auth

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"

	"github.com/TheRebelOfBabylon/weirwood/macaroons"
	"github.com/TheRebelOfBabylon/weirwood/utils"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200)
)

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
