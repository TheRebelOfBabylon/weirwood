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
package macaroons

import (
	"context"
	"encoding/hex"
	"fmt"

	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
	"google.golang.org/grpc/metadata"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2"
)

var (
	PermissionEntityCustomURI = "uri"
	ErrMissingRootKeyID       = fmt.Errorf("Missing root key ID")
)

type MacaroonValidator interface {
	ValidateMacaroon(ctx context.Context, requiredPermissions []bakery.Op, fullMethod string) error
}

type Service struct {
	bakery.Bakery

	rks                *RootKeyStorage
	ExternalValidators map[string]MacaroonValidator
	StatelessInit      bool
}

// InitService returns initializes the rootkeystorage for the Macaroon service and returns the initialized service
func InitService(db kvdb.DB, location string, statelessInit bool, checks ...Checker) (*Service, error) {
	rks, err := InitRootKeyStorage(db)
	if err != nil {
		return nil, err
	}
	bakeryParams := bakery.BakeryParams{
		Location:     location,
		RootKeyStore: rks,
		Locator:      nil,
		Key:          nil,
	}
	service := bakery.New(bakeryParams)
	return &Service{
		Bakery:             *service,
		rks:                rks,
		ExternalValidators: make(map[string]MacaroonValidator),
		StatelessInit:      statelessInit,
	}, nil
}

// isRegistered checks to see if the required checker has already been registered to avoid duplicates
func isRegistered(c *checkers.Checker, name string) bool {
	if c == nil {
		return false
	}
	for _, info := range c.Info() {
		if info.Name == name && info.Prefix == "" && info.Namespace == "std" {
			return true
		}
	}
	return false
}

// RegisterExternalValidator registers a custom, external macaroon validator for
// the specified absolute gRPC URI. That validator is then fully responsible to
// make sure any macaroon passed for a request to that URI is valid and
// satisfies all conditions.
func (svc *Service) RegisterExternalValidator(fullMethod string,
	validator MacaroonValidator) error {

	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}

	_, ok := svc.ExternalValidators[fullMethod]
	if ok {
		return fmt.Errorf("external validator for method %s already "+
			"registered", fullMethod)
	}

	svc.ExternalValidators[fullMethod] = validator
	return nil
}

// ValidateMacaroon validates the capabilities of a given request given a
// bakery service, context, and uri. Within the passed context.Context, we
// expect a macaroon to be encoded as request metadata using the key
// "macaroon".
func (svc *Service) ValidateMacaroon(ctx context.Context,
	requiredPermissions []bakery.Op, fullMethod string) error {

	// Get macaroon bytes from context and unmarshal into macaroon.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("unable to get metadata from context")
	}
	if len(md["macaroon"]) != 1 {
		return fmt.Errorf("expected 1 macaroon, got %d",
			len(md["macaroon"]))
	}

	// With the macaroon obtained, we'll now decode the hex-string
	// encoding, then unmarshal it from binary into its concrete struct
	// representation.
	macBytes, err := hex.DecodeString(md["macaroon"][0])
	if err != nil {
		return err
	}
	mac := &macaroon.Macaroon{}
	err = mac.UnmarshalBinary(macBytes)
	if err != nil {
		return err
	}

	// Check the method being called against the permitted operation, the
	// expiration time and IP address and return the result.
	authChecker := svc.Checker.Auth(macaroon.Slice{mac})
	_, err = authChecker.Allow(ctx, requiredPermissions...)

	// If the macaroon contains broad permissions and checks out, we're
	// done.
	if err == nil {
		return nil
	}

	// To also allow the special permission of "uri:<FullMethod>" to be a
	// valid permission, we need to check it manually in case there is no
	// broader scope permission defined.
	_, err = authChecker.Allow(ctx, bakery.Op{
		Entity: PermissionEntityCustomURI,
		Action: fullMethod,
	})
	return err
}

// Close closes the rootkeystorage of the macaroon service
func (s *Service) Close() error {
	return s.rks.Close()
}

// Thin-wrapper for the CreateUnlock function of the RootKeyStorage attribute of the Service
func (s *Service) CreateUnlock(password *[]byte) error {
	return s.rks.CreateUnlock(password)
}

// ContextWithRootKeyId passes the root key ID value to context
func ContextWithRootKeyId(ctx context.Context, value interface{}) context.Context {
	return context.WithValue(ctx, RootKeyIDContextKey, value)
}

// NewMacaroon is a wrapper around the Oven.NewMacaroon method and returns a freshly baked macaroon
func (s *Service) NewMacaroon(ctx context.Context, rootKeyId []byte, noCaveats bool, cav []checkers.Caveat, ops ...bakery.Op) (*bakery.Macaroon, error) {
	if len(rootKeyId) == 0 {
		return nil, ErrMissingRootKeyID
	}
	ctx = ContextWithRootKeyId(ctx, rootKeyId)
	if !noCaveats {
		return s.Oven.NewMacaroon(ctx, bakery.LatestVersion, nil, ops...)
	}
	return s.Oven.NewMacaroon(ctx, bakery.LatestVersion, cav, ops...)
}

// ChangePassword calls the underlying root key store's ChangePassword and returns the result.
func (svc *Service) ChangePassword(oldPw, newPw []byte) error {
	return svc.rks.ChangePassword(oldPw, newPw)
}
