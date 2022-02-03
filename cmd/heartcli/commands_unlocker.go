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
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/TheRebelOfBabylon/weirwood/auth"
	"github.com/TheRebelOfBabylon/weirwood/heartrpc"
	"github.com/TheRebelOfBabylon/weirwood/utils"
	"github.com/urfave/cli"
)

var (
	statelessInitFlag = cli.BoolFlag{
		Name: "stateless_init",
		Usage: "do not create any macaroon files in the file " +
			"system of the daemon",
	}
	saveToFlag = cli.StringFlag{
		Name:  "save_to",
		Usage: "save returned admin macaroon to this file",
	}
)

var setPassword = cli.Command{
	Name:  "setpassword",
	Usage: "Sets a password when starting weirwood for the first time.",
	Description: `
	Sets a password used to unlock the macaroon key-store when starting weirwood for the first time.
	There is one required argument for this command, the password. There are optional flags for stateless_init
	and save_to for saving the returned macaroon to a specified file.`,
	Flags: []cli.Flag{
		statelessInitFlag,
		saveToFlag,
	},
	Action: setPwd,
}

// setPwd is the proxy command between heartcli and gRPC equivalent.
func setPwd(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUnlockerClient(ctx) //This command returns the proto generated UnlockerClient instance
	defer cleanUp()
	statelessInit := ctx.Bool(statelessInitFlag.Name)
	if !statelessInit && ctx.IsSet(saveToFlag.Name) {
		return fmt.Errorf("Cannot set save_to flag without stateless_init")
	}
	pwd, err := capturePassword(
		"Input new password: ",
	)
	if err != nil {
		return err
	}
	resp, err := client.SetPassword(ctxc, &heartrpc.SetPwdRequest{
		Password:      pwd,
		StatelessInit: statelessInit,
	})
	if err != nil {
		return err
	}
	fmt.Println("\nDaemon unlocked successfully!")
	if statelessInit {
		return storeOrPrintAdminMac(ctx, resp.AdminMacaroon)
	}
	return nil
}

var unlockCommand = cli.Command{
	Name:  "unlock",
	Usage: "Prompts the user to enter the previously set password to unlock the daemon.",
	Description: `
	Prompts the user to enter a password used to unlock the macaroon key-store when starting weirwood.
	There is one required argument for this command, the password.`,
	Action: unlock,
}

// unlock is the proxy command between heartcli and gRPC equivalent.
func unlock(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUnlockerClient(ctx) //This command returns the proto generated UnlockerClient instance
	defer cleanUp()
	pwd, err := auth.ReadPassword("Input password: ")
	if err != nil {
		return err
	}
	_, err = client.UnlockDaemon(ctxc, &heartrpc.UnlockRequest{Password: pwd})
	if err != nil {
		return err
	}
	fmt.Println("\nDaemon unlocked successfully!")
	return nil
}

var changePassword = cli.Command{
	Name:  "changepassword",
	Usage: "Changes the previously set password.",
	Description: `
	Changes the previously set password used to unlock the macaroon key-store.
	There are two required arguments for this command, the old password and the new password. There are optional flags for stateless_init
	and save_to for saving the returned macaroon to a specified file.`,
	Flags: []cli.Flag{
		statelessInitFlag,
		saveToFlag,
		cli.BoolFlag{
			Name: "new_mac_root_key",
			Usage: "rotate the macaroon root key resulting in " +
				"all previously created macaroons to be " +
				"invalidated",
		},
	},
	Action: changePwd,
}

// changePwd is the proxy command between heartcli and gRPC equivalent.
func changePwd(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUnlockerClient(ctx) //This command returns the proto generated UnlockerClient instance
	defer cleanUp()
	statelessInit := ctx.Bool(statelessInitFlag.Name)
	if !statelessInit && ctx.IsSet(saveToFlag.Name) {
		return fmt.Errorf("Cannot set save_to flag without stateless_init")
	}
	oldPwd, err := auth.ReadPassword(
		"Input old password: ",
	)
	if err != nil {
		return err
	}
	newPwd, err := capturePassword(
		"Input new password: ",
	)
	resp, err := client.ChangePassword(ctxc, &heartrpc.ChangePwdRequest{
		CurrentPassword:    oldPwd,
		NewPassword:        newPwd,
		StatelessInit:      statelessInit,
		NewMacaroonRootKey: ctx.Bool("new_mac_root_key"),
	})
	if err != nil {
		return err
	}
	fmt.Println("\nDaemon unlocked successfully!")
	if statelessInit {
		return storeOrPrintAdminMac(ctx, resp.AdminMacaroon)
	}
	return nil
}

// storeOrPrintAdminMac stores the macaroon at the specified file if the save_to flag is provided or prints it to the console
func storeOrPrintAdminMac(ctx *cli.Context, adminMac []byte) error {
	if ctx.IsSet("save_to") {
		macSavePath := ctx.String("save_to")
		if !utils.FileExists(macSavePath) {
			_, err := os.Create(macSavePath)
			if err != nil {
				_ = os.Remove(macSavePath)
				return err
			}
		}
		err := ioutil.WriteFile(macSavePath, adminMac, 0644)
		if err != nil {
			_ = os.Remove(macSavePath)
			return err
		}
		fmt.Printf("Admin macaroon saved to %s\n", macSavePath)
		return nil
	}

	// Otherwise we just print it. The user MUST store this macaroon
	// somewhere so we either save it to a provided file path or just print
	// it to standard output.
	fmt.Printf("Admin macaroon: %s\n", hex.EncodeToString(adminMac))
	return nil
}

// capturePassword captures the password from the terminal and a confirmation of the password
func capturePassword(instruction string) ([]byte, error) {
	for {
		password, err := auth.ReadPassword(instruction)
		if err != nil {
			return nil, err
		}
		pwdConfirmed, err := auth.ReadPassword("Confirm new password: ")
		if bytes.Equal(password, pwdConfirmed) {
			return password, nil
		}
		fmt.Println("Passwords don't match, please try again")
		fmt.Println()
	}
}
