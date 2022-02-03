package weirwood

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestInitLoggerOutput makes sure both console and logfile output work
func TestInitLoggerOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	// start with True
	config := Config{
		DefaultLogDir: true,
		LogFileDir:    default_log_dir(),
		ConsoleOutput: true,
	}
	log, err := InitLogger(&config)
	if err != nil {
		t.Errorf("%s", err)
	}
	log.Info().Msg("Testing both outputs...")
	// False
	config = Config{
		DefaultLogDir: true,
		LogFileDir:    default_log_dir(),
		ConsoleOutput: false,
	}
	log, err = InitLogger(&config)
	if err != nil {
		t.Errorf("%s", err)
	}
	log.Info().Msg("This shouldn't appear in the console...")

	outC := make(chan string)

	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stdout = old
	out := <-outC //reading last line of console output

	if strings.Contains(out, "This shouldn't appear in the console...") {
		t.Errorf("InitLogger produced a logger that prints to console when it shouldn't")
	}
}
