package weirwood

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/TheRebelOfBabylon/weirwood/utils"
	"github.com/google/go-cmp/cmp"
)

// TestInitConfigNoYAML ensures that if no .yaml is found, a default config is produced
func TestInitConfigNoYAML(t *testing.T) {
	home_dir := utils.AppDataDir("weirwood", false)
	if _, err := os.Stat(home_dir + "/config.yaml"); err == nil {
		err = os.Remove(home_dir + "/config.yaml")
		if err != nil {
			t.Errorf("%s", err)
		}
	}
	config, err := InitConfig()
	if err != nil {
		t.Errorf("%s", err)
	}
	// if config != default_config() {
	// 	t.Errorf("InitConfig did not produce a default config when config.yaml was not present")
	// }
	if !cmp.Equal(config, default_config()) {
		t.Errorf("InitConfig did not produce a default config when config.yaml was not present")
	}
}

// TestInitConfigFromYAML ensures that a InitConfig properly reads config files
func TestInitConfigFromYAML(t *testing.T) {
	// first check if config.yaml exists
	home_dir := utils.AppDataDir("weirwood", false)
	config_file, err := os.OpenFile(home_dir+"/config.yaml", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0775)
	if err != nil {
		// might have to create the .weirwood directory and try again
		err = os.Mkdir(home_dir, 0775)
		if err != nil {
			t.Errorf("%s", err)
		}
		config_file, err = os.OpenFile(home_dir+"/config.yaml", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0775)
		if err != nil {
			t.Errorf("%s", err)
		}
	}
	// write to yaml file
	d_config := Config{
		DefaultLogDir:  false,
		LogFileDir:     "/home/vagrant/documents",
		ConsoleOutput:  true,
		GrpcPort:       4567,
		RestPort:       8080,
		TLSCertPath:    default_tls_cert_path,
		TLSKeyPath:     default_tls_key_path,
		DBPath:         default_db_file,
		AdminMacPath:   default_admin_macaroon_path,
		TestMacPath:    test_macaroon_path,
		WSPingInterval: time.Second * 30,
		WSPongWait:     time.Second * 5,
	}
	_, err = config_file.WriteString(fmt.Sprintf("DefaultLogDir: %v\n", d_config.DefaultLogDir))
	if err != nil {
		t.Errorf("%s", err)
	}
	_, err = config_file.WriteString(fmt.Sprintf("LogFileDir: %v\n", d_config.LogFileDir))
	if err != nil {
		t.Errorf("%s", err)
	}
	_, err = config_file.WriteString(fmt.Sprintf("ConsoleOutput: %v\n", d_config.ConsoleOutput))
	if err != nil {
		t.Errorf("%s", err)
	}
	_, err = config_file.WriteString(fmt.Sprintf("GrpcPort: %v\n", d_config.GrpcPort))
	if err != nil {
		t.Errorf("%s", err)
	}
	_, err = config_file.WriteString(fmt.Sprintf("RestPort: %v\n", d_config.RestPort))
	if err != nil {
		t.Errorf("%s", err)
	}
	config_file.Sync()
	config_file.Close()
	config, err := InitConfig()
	if err != nil {
		t.Errorf("%s", err)
	}
	if !cmp.Equal(config, d_config) {
		t.Errorf("InitConfig did not properly read the config file: %v", config)
	}
}

// TestDefaultLogDir tests that default_log_dir returns the expected default log directory
func TestDefaultLogDir(t *testing.T) {
	home_dir := utils.AppDataDir("weirwood", false)
	log_dir := home_dir
	if log_dir != default_log_dir() {
		t.Errorf("default_log_dir not returning expected directory. Expected: %s\tReceived: %s", log_dir, default_log_dir())
	}
}

// TestDefaultConfig checks if default_config does return the expected default config struct
func TestDefaultConfig(t *testing.T) {
	d_config := Config{
		DefaultLogDir:  true,
		LogFileDir:     default_log_dir(),
		ConsoleOutput:  true,
		GrpcPort:       default_grpc_port,
		RestPort:       default_rest_port,
		TLSCertPath:    default_tls_cert_path,
		TLSKeyPath:     default_tls_key_path,
		DBPath:         default_db_file,
		AdminMacPath:   default_admin_macaroon_path,
		TestMacPath:    test_macaroon_path,
		WSPingInterval: time.Second * 30,
		WSPongWait:     time.Second * 5,
	}
	if !cmp.Equal(d_config, default_config()) {
		t.Errorf("default_config not returning expected config. Expected: %v\tReceived: %v", d_config, default_config())
	}
}
