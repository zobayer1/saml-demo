package config

import (
	"sync"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Host     string `envconfig:"HOST"         default:":8001"`
	CertPath string `envconfig:"CERT_PATH"                                             required:"true"`
	KeyPath  string `envconfig:"KEY_PATH"                                              required:"true"`
	// SAML specific settings
	IDPSSOURL   string `envconfig:"IDP_SSO_URL"  default:"https://idp.localhost:8000/sso"`
	EntityID    string `envconfig:"ENTITY_ID"    default:"urn:samldemo:sp1"`
	ACSURL      string `envconfig:"ACS_URL"      default:"https://sp1.localhost:8001/acs"`
	IDPMetadata string `envconfig:"IDP_METADATA" default:"etc/saml/idp-metadata.xml"`
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
