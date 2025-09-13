package config

import (
	"sync"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Host     string `envconfig:"HOST"           default:":8002"`
	CertPath string `envconfig:"CERT_PATH"                                                        required:"true"`
	KeyPath  string `envconfig:"KEY_PATH"                                                         required:"true"`
	// SAML specific settings for initiating AuthnRequest
	IDPSSOURL    string `envconfig:"IDP_SSO_URL"    default:"https://idp.localhost:8000/sso"`
	IDPSLOURL    string `envconfig:"IDP_SLO_URL"    default:"https://idp.localhost:8000/slo"`
	EntityID     string `envconfig:"ENTITY_ID"      default:"urn:samldemo:sp2"`
	ACSURL       string `envconfig:"ACS_URL"        default:"https://sp2.localhost:8002/acs"`
	SLOReturnURL string `envconfig:"SLO_RETURN_URL" default:"https://sp2.localhost:8002/slo/complete"`
	IDPMetadata  string `envconfig:"IDP_METADATA"   default:"etc/saml/idp-metadata.xml"`
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
