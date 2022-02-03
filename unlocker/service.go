package unlocker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"

	"github.com/TheRebelOfBabylon/weirwood/heartrpc"
	"github.com/TheRebelOfBabylon/weirwood/kvdb"
	"github.com/TheRebelOfBabylon/weirwood/macaroons"
	"github.com/TheRebelOfBabylon/weirwood/utils"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
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
	heartrpc.UnimplementedUnlockerServer
	PassChan      chan *PasswordMsg
	MacRespChan   chan []byte
	macaroonDB    *kvdb.DB
	macaroonFiles []string
}

// This tests whether *UnlockerService implements the ElligibleRestService Interface
var _ utils.ElligibleRestService = (*UnlockerService)(nil)

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

// Stop is a cleanup function to close channels on daemon shutdown
func (u *UnlockerService) Stop() error {
	close(u.MacRespChan)
	close(u.PassChan)
	return nil
}

// RegisterWithGrpcServer registers the gRPC server to the unlocker service
func (u *UnlockerService) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	heartrpc.RegisterUnlockerServer(grpcServer, u)
	return nil
}

// RegisterWithRestProxy registers the UnlockerService with the REST proxy
func (u *UnlockerService) RegisterWithRestProxy(ctx context.Context, mux *proxy.ServeMux, restDialOpts []grpc.DialOption, restProxyDest string) error {
	err := heartrpc.RegisterUnlockerHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}
	return nil
}

// setPassword will set the password if one has not already been set
func (u *UnlockerService) setPassword(password []byte, overwrite bool) error {
	u.macaroonDB.Mutex.Lock()
	defer u.macaroonDB.Mutex.Unlock()
	return u.macaroonDB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(pwdKeyBucketName) // get the password bucket
		if bucket == nil {
			return fmt.Errorf("Password bucket not found")
		}
		pwd := bucket.Get(pwdKeyID) //get the password kv pair
		if len(pwd) > 0 && !overwrite {
			tx.Rollback()
			return ErrPasswordAlreadySet
		}
		// no pwd has been set or a new one has been given
		hash := sha256.Sum256(password)
		err := bucket.Put(pwdKeyID, hash[:])
		if err != nil {
			tx.Rollback()
			return err
		}
		return nil
	})
}

// readPassword will read the password provided and compare to what's in the db
func (u *UnlockerService) readPassword(password []byte) error {
	u.macaroonDB.Mutex.Lock()
	defer u.macaroonDB.Mutex.Unlock()
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
func (u *UnlockerService) SetPassword(ctx context.Context, req *heartrpc.SetPwdRequest) (*heartrpc.SetPwdResponse, error) {
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
			return &heartrpc.SetPwdResponse{
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
func (u *UnlockerService) UnlockDaemon(ctx context.Context, req *heartrpc.UnlockRequest) (*heartrpc.UnlockResponse, error) {
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
			return &heartrpc.UnlockResponse{}, nil
		case <-ctx.Done():
			return nil, ErrUnlockTimeout
		}
	case <-ctx.Done():
		return nil, ErrUnlockTimeout
	}
}

// ChangePassword takes the old password, validates it and sets the new password from the inputted new password only if a previous password has been set
func (u *UnlockerService) ChangePassword(ctx context.Context, req *heartrpc.ChangePwdRequest) (*heartrpc.ChangePwdResponse, error) {
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
			return &heartrpc.ChangePwdResponse{
				AdminMacaroon: adminMac,
			}, nil
		case <-ctx.Done():
			return nil, ErrUnlockTimeout
		}

	case <-ctx.Done():
		return nil, ErrUnlockTimeout
	}
}
