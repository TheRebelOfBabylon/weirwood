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
package auth

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcwallet/snacl"
	macaroon "gopkg.in/macaroon.v2"
)

const (
	encryptionPrefix = "snacl:"
)

type getPasswordFunc func(prompt string) ([]byte, error)

// decryptMacaroon will take a password and derive the priv key using the provided password to then decrypt the macaroon
func decryptMacaroon(keyBase64, dataBase64 string, pw []byte) ([]byte, error) {
	keyData, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("Could not base64 decode encryption key: %v", err)
	}
	encryptedMac, err := base64.StdEncoding.DecodeString(dataBase64)
	if err != nil {
		return nil, fmt.Errorf("Could not base64 decode encrypted macaroon: %v", err)
	}
	key := &snacl.SecretKey{}
	err = key.Unmarshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshall encryption key: %v", err)
	}
	err = key.DeriveKey(&pw)
	if err != nil {
		return nil, fmt.Errorf("Could not derive encryption key possibly due to incorrect password: %v", err)
	}
	macBytes, err := key.Decrypt(encryptedMac)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt macaroon: %v", err)
	}
	return macBytes, nil
}

// loadMacaroon takes a password prompting function and hex encoded macaroon and returns an instantiated macaroon object
func loadMacaroon(pwCallback getPasswordFunc, macHex string) (*macaroon.Macaroon, error) {
	if len(strings.TrimSpace(macHex)) == 0 {
		return nil, fmt.Errorf("macaroon data is empty")
	}
	var (
		macBytes []byte
		err      error
	)
	if strings.HasPrefix(macHex, encryptionPrefix) {
		parts := strings.Split(macHex, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("Invalid encrypted macaroon. Format expected: 'snacl:<key_base64>:<encrypted_macaroon_base64>'")
		}
		pw, err := pwCallback("Enter macaroon encryption password: ")
		if err != nil {
			return nil, fmt.Errorf("Could not read password from terminal: %v", err)
		}
		macBytes, err = decryptMacaroon(parts[1], parts[2], pw)
		if err != nil {
			return nil, fmt.Errorf("Unable to decrypt macaroon: %v", err)
		}
	} else {
		macBytes, err = hex.DecodeString(macHex)
		if err != nil {
			return nil, fmt.Errorf("Unable to hex decode macaroon: %v", err)
		}
	}
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("Unable to decode macaroon: %v", err)
	}
	return mac, nil
}
