package config

import (
	"sync"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Host     string `envconfig:"HOST"      default:":8001"`
	SqliteDb string `envconfig:"SQLITE_DB"                 required:"true"`
	CertPath string `envconfig:"CERT_PATH"                 required:"true"`
	KeyPath  string `envconfig:"KEY_PATH"                  required:"true"`
}

var (
	instance *Config
	once     sync.Once
)

func NewConfig() (*Config, error) {
	var err error
	once.Do(func() {
		var config Config
		if err = envconfig.Process("", &config); err != nil {
			return
		}
		instance = &config
	})
	return instance, err
}
