package weirwood

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/mattn/go-colorable"
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
		// try to create the .weirwood dir and try again if log dir is default log dir
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
		output := zerolog.NewConsoleWriter()
		if runtime.GOOS == "windows" {
			output.Out = colorable.NewColorableStdout()
		} else {
			output.Out = os.Stderr
		}
		output.FormatLevel = func(i interface{}) string {
			var msg string
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
			return msg + fmt.Sprintf("\t")
		}
		multi := zerolog.MultiLevelWriter(output, log_file)
		logger = zerolog.New(multi).With().Timestamp().Logger()
	} else {
		logger = zerolog.New(log_file).With().Timestamp().Logger()
	}
	return logger, nil
}

// NewSubLogger takes a `zerolog.Logger` and string for the name of the subsystem and creates a `subLogger` for this subsystem
func NewSubLogger(l *zerolog.Logger, subsystem string) *zerolog.Logger {
	sub := l.With().Str("subsystem", subsystem).Logger()
	return &sub
}
