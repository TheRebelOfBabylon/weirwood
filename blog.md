# LND Under the Hood Part 1: How to create a daemon

## Introduction

As development of Bitswarm continues, it has come to the Bitswarm teams attention that using Django to build the API may not be sufficient. We decided it would be best to create our own daemon to act as a Bitswarm node. And what better model to follow than LNDs. The aim of this series of blog posts is to document the process I undertook while deconstructing the underlying code of LND and modifying it to suit the purposes of the development of the Bitswarm daemon. Hopefully in the process, you dear reader, will also have learned something.

## Step 0: Directory Structure

To save you alot of time and effort, I have identified the relevant and what I believe to be foundational parts of the daemon for the purposes of building a "general purpose" daemon. This daemon will log, read config from a config file, bake and validate macaroons, exectute RPCs from either the gRPC, REST or CLI interface and authenticate those RPCs using macaroons. Here is what the directory structure will look like:
```
/bitswarmd
	/auth
		connection.go
		macaroon_jar.go
    /bitswarm
        bitswarm.go
        config_test.go
        config.go
        log_test.go
        log.go
        rpcserver.go
        server.go
    /cert
        tls.go
    /cmd
        /bitswarmd
            main.go
        /swarmcli
			commands_unlocker.go
            commands.go
            main.go
    /intercept
        grpc_intercept.go
        intercept.go
	/kvdb
		db.go
    /macaroons
        auth.go
        constraints_test.go
        constraints.go
        service_test.go
        service.go
        store_test.go
        store.go
    /swarmrpc
		gen_protos.sh
        swarm.proto
		swarm.yaml
		unlocker.proto
		unlocker.yaml
        websocket_proxy.go
	/unlocker
		service.go
    /utils
        address.go
        address_test.go
        appdata.go
        general.go
    Makefile
```
I've moved some files such as `server.go`, `rpcserver.go` and `lnd.go` (which in this project is `bitswarm.go`) to a folder called `bitswarm` since all files in the `bitswarm` folder are part of the `bitswarm` package. I've also made some additions, particularly with the `utils` package which will come in handy later. You'll also notice that I've included many test files: unit testing is important and should be done where possible. Especially since go makes it so easy to do with built in unit testing capabilities.

## Step 1: Log and Config

First, let us define our config package as we will be using the config to initialize the rest of our tools. LND reads configuration from `lnd.conf` or from command line arguments. For this project, we will read configuration from a `config.yaml` file. If a file is not defined, then it will use default values that we will define in the `config.go` file. Let's begin by defining a `Config` struct which will hold all our configuration parameters.

```
package bitswarm

import (
    "io/ioutil"
    "log"
    "os"
    "path/filepath"
    "reflect"
    yaml "gopkg.in/yaml.v2"
)

type Config struct {
    DefaultLogDir	bool 		`yaml:"DefaultLogDir"`
	LogFileDir 		string		`yaml:"LogFileDir"`
	ConsoleOutput	bool		`yaml:"ConsoleOutput"`
}
```
Notice the tags at the end of each attribute. This is important so that when we read the yaml file, it will know which attributes to associate with what values. Let's define a `InitConfig()` function so that we can initialize our config as well as any helper functions to make this work.

```
// all default values will be defined here
var (
    default_log_dir = func() string {
		home_dir, err := os.UserHomeDir() // this should be OS agnostic
		if err != nil {
		    log.Fatal(err)
		}
		return home_dir+"/.bitswarmd"
	}
    default_config = func() Config {
		return &Config{
			DefaultLogDir: true,
			LogFileDir: default_log_dir(),
			ConsoleOutput: false,
		}
	}
)

// InitConfig returns an instantiated config struct either read from a yaml file or a default config
func InitConfig() (Config, error) {
    filename, _ := filepath.Abs(default_log_dir()+"/config.yaml")
	config_file, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println(err)
		return default_config(), nil
	}
	var config Config
	err = yaml.Unmarshal(config_file, &config)
	if err != nil {
		log.Println(err)
		config = default_config() // if we can't read the yaml file, resort to default config
	} else {
		// Need to check if any config parameters aren't defined in `config.yaml` and assign them a default value
		config = check_yaml_config(config)
	}
	return config, nil
}

// check_yaml_config assigns default values to any empty attributes that were not defined in the yaml file
func check_yaml_config(config Config) Config {
	pv := reflect.ValueOf(&config)
	v := pv.Elem()
	field_names := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		field_name := field_names.Field(i).Name
		switch field_name {
		case "LogFileDir":
			if f.String() == "" {
				change_field(f, default_log_dir())
				dld := v.FieldByName("DefaultLogDir")
				change_field(dld, true)
			}
		}
	}
	return config
}

// change_field changes the value of a specified field from the config struct
func change_field(field reflect.Value, new_value interface{}) {
	if field.IsValid() {
		if field.CanSet() {
			f := field.Kind()
			switch f {
			case reflect.String:
				if v, ok := new_value.(string); ok {
					field.SetString(v)
				} else {
					log.Fatal(fmt.Sprintf("Type of new_value: %v does not match the type of the field: string", new_value))
				}
			case reflect.Bool:
				if v, ok := new_value.(bool); ok {
					field.SetBool(v)
				} else {
					log.Fatal(fmt.Sprintf("Type of new_value: %v does not match the type of the field: bool", new_value))
				}
			case reflect.Int64:
				if v, ok := new_value.(int64); ok {
					field.SetInt(v)
				} else {
					log.Fatal(fmt.Sprintf("Type of new_value: %v does not match the type of the field: int64", new_value))
				}
			}
		}
	}
}
```
So that we can properly test everything, we might as well implement the main entry point for bitswarmd/lnd which is the `main.go` file in `cmd/bitswarmd`.

```
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
	"fmt"
	"os"

	"gitlab.com/cypher-engineers/bitswarmd/bitswarm"
)

func main() {
	_, err := bitswarm.InitConfig()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```
And then to run this code, we enter the following commands:
```
$ GO111MODULE=on go install -v gitlab.com/cypher-engineers/bitswarmd/cmd/bitswarmd
$ bitswarmd
```
We can't forget that copyright notice whenever we are copying and or modifiying files directly from the LND project. If compiling main yields no errors, then we can move onto the log.

For logging, LND uses btclog from the btcsuite. I decided that for this project, I would use zerolog. Feel free to use any package that suites your project best.

```
package bitswarm

import (
	"fmt"
	"os"
	"strings"

	color "github.com/mgutz/ansi"
	"github.com/rs/zerolog"
)

var (
	logFileName = "logfile.log"
)

// InitLogger instantiates the logger object from the zerolog package
func InitLogger(config *Config) (zerolog.Logger, error) {
	var (
		log_file *os.File
		err      error
		logger   zerolog.Logger
	)
	log_file, err = os.OpenFile(config.LogFileDir+"/"+logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0775)
	if err != nil {
		// try to create the .bitswarmd dir and try again if log dir is default log dir
		if config.DefaultLogDir {
			err = os.Mkdir(config.LogFileDir, 0775)
			if err != nil {
				return zerolog.Logger{}, err
			}
			log_file, err = os.OpenFile(config.LogFileDir+"/"+logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0775)
			if err != nil {
				return zerolog.Logger{}, err
			}
		} else {
			return zerolog.Logger{}, err
		}
	}

	// if consoleOutput is true, then we instantiate zerolog.Logger with both logfile and console writting
	if config.ConsoleOutput {
		output := zerolog.ConsoleWriter{Out: os.Stderr}
		output.FormatLevel = func(i interface{}) string {
			var msg string
            // the colours don't work on Windows cmd
			if runtime.GOOS == "windows" {
				switch v := i.(type) {
				default:
					x := fmt.Sprintf("%v", v)
					switch x {
					case "info":
						msg = strings.ToUpper("[" + x + "]")
					case "panic":
						msg = strings.ToUpper("[" + x + "]")
					case "fatal":
						msg = strings.ToUpper("[" + x + "]")
					case "error":
						msg = strings.ToUpper("[" + x + "]")
					case "debug":
						msg = strings.ToUpper("[" + x + "]")
					case "trace":
						msg = strings.ToUpper("[" + x + "]")
					}
				}
			} else {
				switch v := i.(type) {
				default:
					x := fmt.Sprintf("%v", v)
					switch x {
					case "info":
						msg = color.Color(strings.ToUpper("["+x+"]"), "green")
					case "panic":
						msg = color.Color(strings.ToUpper("["+x+"]"), "red")
					case "fatal":
						msg = color.Color(strings.ToUpper("["+x+"]"), "red")
					case "error":
						msg = color.Color(strings.ToUpper("["+x+"]"), "red")
					case "debug":
						msg = color.Color(strings.ToUpper("["+x+"]"), "yellow")
					case "trace":
						msg = color.Color(strings.ToUpper("["+x+"]"), "magenta")
					}
				}
			}
			return msg + fmt.Sprintf("\t")
		}
		multi := zerolog.MultiLevelWriter(output, log_file)
		logger = zerolog.New(multi).With().Timestamp().Logger()
	} else {
		logger = zerolog.New(log_file).With().Timestamp().Logger()
	}
	return logger, nil
}
```
Now let us actually store the returned `Config` from `InitConfig()` in a variable and use that variable in `InitLogger()` in `main.go`
```
func main() {
    config, err = bitswarm.InitConfig()
    ...
    log, err := bitswarm.InitLogger(&config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log.Info().Msg("Test")
}
```
Lastly, we will create some unit tests for our config and logging tools and put them in `config_test.go` and `log_test.go`.

## Step 2: Server file

The next step is to create the server struct that will hold all the relevant attributes to running the main daemon process including the configuration and logger.

```
package bitswarm

import (
	"fmt"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// Server is the object representing the state of the server
type Server struct {
	Active   int32 // atomic
	Stopping int32 // atomic
	cfg      *Config
	logger   *zerolog.Logger
}

// InitServer creates a new instance of the server and returns a pointer to it
func InitServer(config *Config, logger *zerolog.Logger) (*Server, error) {
	return &Server{
		cfg:    config,
		logger: logger,
	}, nil
}

// Start starts the server. Returns an error if any issues occur
func (s *Server) Start() error {
	s.logger.Info().Msg("Starting daemon...")
	if ok := atomic.CompareAndSwapInt32(&s.Active, 0, 1); !ok {
		return fmt.Errorf("Could not set daemon to ready: daemon already ready.")
	}
	return nil
}

// Stop stops the server. Returns an error if any issues occur
func (s *Server) Stop() error {
	s.logger.Info().Msg("Stopping daemon...")
	if ok := atomic.CompareAndSwapInt32(&s.Active, 1, 0); !ok {
		return fmt.Errorf("Could not stop daemon: daemon already stopped.")
	}
	return nil
}
```
And then instantiating the server object in our `main.go`.

```
func main() {
    config, err = bitswarm.InitConfig()
    ...
    _, err = bitswarm.InitServer(&config, &log)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```
We are almost done building the `bitswarm` package. The last things we need to do are create the rpcserver struct and then create the equivalent of `lnd.go` to serve as the main entry point of the daemon process. Before we do that, we will create the `intercept` package and create the shutdown interceptor.

## Step 3: Shutdown Interceptor

This step is quite short as we are going to basically copy and paste the intercept package made in the LND repository. I've made slight modifications to use the zerolog logger package instead of the btc logger package LND uses. Feel free to replicate my changes with the logger of your choice.

```
package intercept

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/rs/zerolog"
)

var (
	started int32
)

// Interceptor is the object controlling application shutdown requests
type Interceptor struct {
	interruptChannel       chan os.Signal
	Logger                 *zerolog.Logger
	shutdownChannel        chan struct{}
	shutdownRequestChannel chan struct{}
	quit                   chan struct{}
}

// mainInterruptHandler listens for SIGINT (Ctrl+C) signals on the interruptChannel and shutdown requests on the
// shutdownRequestChannel.
func (interceptor *Interceptor) mainInterruptHandler() {
	defer atomic.StoreInt32(&started, 0)
	var isShutdown bool
	shutdown := func() {
		if isShutdown {
			if interceptor.Logger != nil {
				interceptor.Logger.Info().Msg("Already shutting down...")
			} else {
				log.Println("Already shutting down...")
			}
			return
		}
		isShutdown = true
		if interceptor.Logger != nil {
			interceptor.Logger.Info().Msg("Shutting down...")
		} else {
			log.Println("Shutting down...")
		}
		close(interceptor.quit)
	}
	for {
		select {
		case signal := <-interceptor.interruptChannel:
			if interceptor.Logger != nil {
				interceptor.Logger.Info().Msg(fmt.Sprintf("Received %v", signal))
			} else {
				log.Printf("Received %v", signal)
			}
			shutdown()
		case <-interceptor.shutdownRequestChannel:
			if interceptor.Logger != nil {
				interceptor.Logger.Info().Msg("Received shutdown request.")
			} else {
				log.Println("Received shutdown request.")
			}
			shutdown()
		case <-interceptor.quit:
			if interceptor.Logger != nil {
				interceptor.Logger.Info().Msg("Gracefully shutting down.")
			} else {
				log.Println("Gracefully shutting down.")
			}
			close(interceptor.shutdownChannel)
			signal.Stop(interceptor.interruptChannel)
			return
		}
	}
}

// RequestShutdown initiates a graceful shutdown from the application.
func (interceptor *Interceptor) RequestShutdown() {
	select {
	case interceptor.shutdownRequestChannel <- struct{}{}:
	case <-interceptor.quit:
	}
}

// ShutdownChannel returns the channel that will be closed once the main
// interrupt handler has exited.
func (c *Interceptor) ShutdownChannel() <-chan struct{} {
	return c.shutdownChannel
}

// InitInterceptor initializes the shutdown and interrupt interceptor
func InitInterceptor() (*Interceptor, error) {
	if !atomic.CompareAndSwapInt32(&started, 0, 1) {
		return &Interceptor{}, errors.New("Interceptor already initialized")
	}
	interceptor := Interceptor{
		interruptChannel:       make(chan os.Signal, 1),
		shutdownChannel:        make(chan struct{}),
		shutdownRequestChannel: make(chan struct{}),
		quit:                   make(chan struct{}),
	}
	signalsToCatch := []os.Signal{
		os.Interrupt,
		os.Kill,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	}
	signal.Notify(interceptor.interruptChannel, signalsToCatch...)
	go interceptor.mainInterruptHandler()
	return &interceptor, nil
}
```
Essentially, this allows us to listen for interupt signals in any goroutine and is needed in order to shutdown the node safely when you enter CTRL+C in the command line. We will now instantiate the `Interceptor` struct in our `main.go`.
```
func main() {
	shutdownInterceptor, err := intercept.InitInterceptor()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
    config, err = bitswarm.InitConfig()
    ...
	shutdownInterceptor.Logger = &log
    _, err = bitswarm.InitServer(&config, &log)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

## Step 4: The real Main()

The final step in this first part will be to create the true entry point for `bitswarmd` found in the `bitswarm.go` file. The main execution of the code is isolated in this `Main()` function for convenience. We won't be touching `main.go` after this.

In the `bitswarm.go` file, we will declare a function `Main()` where we will call the `Start()` method of the `Server` struct, defer the `Stop()` function and then hang on the receive SIGINT signal channel of our interceptor.

```
package bitswarm

import (
	"fmt"

	"gitlab.com/cypher-engineers/bitswarmd/intercept"
)

// Main is the true entry point for bitswarmd. It's called in a nested manner for proper defer execution
func Main(interceptor *intercept.Interceptor, server *Server) error {
	// Starting main server
	err := server.Start()
	if err != nil {
		server.logger.Fatal().Msg(fmt.Sprintf("Could not start daemon: %v", err))
		return err
	}
	defer server.Stop()

	// Listen for shutdown signals
	<-interceptor.ShutdownChannel()
	return nil
}
```

Then back to `main.go`, we will call the `Main()` function and pass the interceptor and server we previously instantiated.

```
func main() {
    ...
	if err = bitswarm.Main(shutdownInterceptor, server); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

We can now finally build and try out our daemon.

```
$ GO111MODULE=on go install -v gitlab.com/cypher-engineers/bitswarmd/cmd/bitswarmd
gitlab.com/cypher-engineers/bitswarmd/intercept
gitlab.com/cypher-engineers/bitswarmd/bitswarm
gitlab.com/cypher-engineers/bitswarmd/cmd/bitswarmd
$ bitswarmd
2022/01/25 13:51:15 open ~/.bitswarmd/config.yaml: no such file or directory
1:51PM [INFO]    Starting daemon...
^C1:51PM [INFO]         Received interrupt
1:51PM [INFO]    Shutting down...
1:51PM [INFO]    Gracefully shutting down.
1:51PM [INFO]    Stopping daemon...
```

## Conclusion

This concludes the first part of the *LND Under the Hood* series. In the next part, we will learn how to integrate gRPC, REST as well as how to build a command line tool to accompany our daemon. Hope you enjoyed reading. 