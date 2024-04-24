package user

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/session"
)

const (
	EnvCaCert       string = "SHAW_CA_CERT"
	EnvServerCert   string = "SHAW_SERVER_CERT"
	EnvServerKey    string = "SHAW_SERVER_KEY"
	EnvClientCert   string = "SHAW_CLIENT_CERT"
	EnvClientKey    string = "SHAW_CLIENT_KEY"
	EnvDbClientCert string = "SHAW_DB_CLIENT_CERT"
	EnvDbClientKey  string = "SHAW_DB_CLIENT_KEY"

	// db config
	EnvDbUrl       string = "SHAW_DATABASE_URL"
	EnvDbName      string = "SHAW_DATABASE_NAME"
	EnvDbUsername  string = "SHAW_DATABASE_USERNAME"
	EnvDbPassword  string = "SHAW_DATABASE_PASSWORD"
	EnvDbIndexHmac string = "SHAW_DATABASE_INDEX_HMAC"

	// field level encryption
	EnvFieldsKey string = "SHAW_FIELD_LEVEL_AES_GCM_KEY"

	// ran s2s authn
	EnvS2sTokenUrl  string = "SHAW_S2S_AUTH_URL"
	EnvClientId     string = "SHAW_S2S_AUTH_CLIENT_ID"
	EnvClientSecret string = "SHAW_S2S_AUTH_CLIENT_SECRET"
)

func TestRegister(t *testing.T) {

	// set up auth server db client
	authServerDbClientPki := &connect.Pki{
		CertFile: os.Getenv(EnvDbClientCert),
		KeyFile:  os.Getenv(EnvDbClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}
	authServerDbClientConfig := connect.ClientConfig{Config: authServerDbClientPki}

	authServerDbUrl := data.DbUrl{
		Name:     os.Getenv(EnvDbName),
		Addr:     os.Getenv(EnvDbUrl),
		Username: os.Getenv(EnvDbUsername),
		Password: os.Getenv(EnvDbPassword),
	}

	authServerDbConector := &data.MariaDbConnector{
		TlsConfig:     authServerDbClientConfig,
		ConnectionUrl: authServerDbUrl.Build(),
	}

	authServerDao := &data.MariaDbRepository{
		SqlDb: authServerDbConector,
	}

	// set up field level encryption cryptor
	aes, _ := base64.StdEncoding.DecodeString(os.Getenv(EnvFieldsKey))
	t.Logf("%d", len(aes))
	cryptor := data.NewServiceAesGcmKey(aes)

	// set up indexer
	hmacSecret, _ := base64.StdEncoding.DecodeString(os.Getenv(EnvDbIndexHmac))
	indexer := data.NewHmacIndexer(hmacSecret)

	// set up s2s provider
	s2sClientPki := connect.Pki{
		CertFile: os.Getenv(EnvClientCert),
		KeyFile:  os.Getenv(EnvClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	s2sClientConfig := connect.ClientConfig{Config: &s2sClientPki}
	s2sClient, _ := s2sClientConfig.NewTlsClient()

	s2sCreds := session.S2sCredentials{
		ClientId:     os.Getenv(EnvClientKey),
		ClientSecret: os.Getenv(EnvClientSecret),
	}

	// retry config for s2s callers
	retry := connect.RetryConfiguration{
		MaxRetries:  5,
		BaseBackoff: 100 * time.Microsecond,
		MaxBackoff:  10 * time.Second,
	}

	// s2s callers
	ranCaller := connect.NewS2sCaller(os.Getenv(EnvS2sTokenUrl), "ran", s2sClient, retry)

	s2sJwtProvder := session.NewS2sTokenProvider(ranCaller, s2sCreds, authServerDao, cryptor)

	authRegistrationService := NewAuthRegistrationService(authServerDao, cryptor, indexer, s2sJwtProvder, ranCaller)

	cmd := session.UserRegisterCmd{
		Username:  "darth.vader@empire.com",
		Password:  "2-Suns-Tattooine",
		Confirm:   "2-Suns-Tattooine",
		Firstname: "Darth",
		Lastname:  "Vader",
		Birthdate: "1977-05-25", // A New Hope release date
	}

	if err := authRegistrationService.Register(cmd); err != nil {
		t.Logf("test registration failed: %v", err)
		t.Fail()
	}

}
