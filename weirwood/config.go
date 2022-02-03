package weirwood

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"reflect"
	"time"

	"github.com/TheRebelOfBabylon/weirwood/utils"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	DefaultLogDir  bool     `yaml:"DefaultLogDir"`
	LogFileDir     string   `yaml:"LogFileDir"`
	ConsoleOutput  bool     `yaml:"ConsoleOutput"`
	GrpcPort       int64    `yaml:"GrpcPort"`
	RestPort       int64    `yaml:"RestPort"`
	ExtraIPAddr    []string `yaml:"ExtraIPAddr"` // optional parameter
	TLSCertPath    string
	TLSKeyPath     string
	DBPath         string
	AdminMacPath   string
	TestMacPath    string
	WSPingInterval time.Duration
	WSPongWait     time.Duration
}

// all default values will be defined here
var (
	default_log_dir = func() string {
		return utils.AppDataDir("weirwood", false)
	}
	default_grpc_port           int64  = 4567
	default_rest_port           int64  = 8080
	default_ws_ping_interval           = time.Second * 30
	default_ws_pong_wait               = time.Second * 5
	default_tls_cert_path       string = default_log_dir() + "/tls.cert"
	default_tls_key_path        string = default_log_dir() + "/tls.key"
	default_db_file             string = default_log_dir() + "/db.db"
	default_admin_macaroon_path string = default_log_dir() + "/admin.macaroon"
	test_macaroon_path          string = default_log_dir() + "/test.macaroon"
	default_config                     = func() Config {
		return Config{
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
			WSPingInterval: default_ws_ping_interval,
			WSPongWait:     default_ws_pong_wait,
		}
	}
)

// InitConfig returns an instantiated config struct either read from a yaml file or a default config
func InitConfig() (Config, error) {
	filename, _ := filepath.Abs(default_log_dir() + "/config.yaml")
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
	config.WSPingInterval = default_ws_ping_interval
	config.WSPongWait = default_ws_pong_wait
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
		case "GrpcPort":
			if f.Int() == 0 {
				change_field(f, default_grpc_port)
			}
		case "RestPort":
			if f.Int() == 0 {
				change_field(f, default_rest_port)
			}
		case "TLSCertPath":
			if f.String() == "" {
				change_field(f, default_tls_cert_path)
				tls_key := v.FieldByName("TLSKeyPath")
				change_field(tls_key, default_tls_key_path)
			}
		case "TLSKeyPath":
			if f.String() == "" {
				change_field(f, default_tls_key_path)
				tls_cert := v.FieldByName("TLSCertPath")
				change_field(tls_cert, default_tls_cert_path)
			}
		case "DBPath":
			if f.String() == "" {
				change_field(f, default_db_file)
			}
		case "AdminMacPath":
			if f.String() == "" {
				change_field(f, default_admin_macaroon_path)
			}
		case "TestMacPath":
			if f.String() == "" {
				change_field(f, test_macaroon_path)
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
