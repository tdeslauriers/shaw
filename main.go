package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/jwt"
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

	// signing jwts
	EnvJwtSigningKey string = "SHAW_JWT_SIGNING_KEY"

	// verifying s2s jwts
	EnvS2sJwtVerifyKey string = "RAN_JWT_VERIFYING_KEY"
)

func main() {

	// set up server pki
	serverPki := &connect.Pki{
		CertFile: os.Getenv(EnvServerCert),
		KeyFile:  os.Getenv(EnvServerKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	mtls, err := connect.NewTLSConfig("mutual", serverPki)
	if err != nil {
		log.Fatalf("unable to configure mutual tls: %v", err)
	}

	// set up s2s client
	clientPki := connect.Pki{
		CertFile: os.Getenv(EnvClientCert),
		KeyFile:  os.Getenv(EnvClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	clientConfig := connect.ClientConfig{Config: &clientPki}
	client, err := clientConfig.NewTlsClient()
	if err != nil {
		log.Fatalf("Unable to create shaw s2s client config: %v", err)
	}

	// set up db
	dbClientPki := &connect.Pki{
		CertFile: os.Getenv(EnvDbClientCert),
		KeyFile:  os.Getenv(EnvDbClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	dbClientConfig := connect.ClientConfig{Config: dbClientPki}

	dbUrl := data.DbUrl{
		Name:     os.Getenv(EnvDbName),
		Addr:     os.Getenv(EnvDbUrl),
		Username: os.Getenv(EnvDbUsername),
		Password: os.Getenv(EnvDbPassword),
	}

	dbConnector := &data.MariaDbConnector{
		TlsConfig:     dbClientConfig,
		ConnectionUrl: dbUrl.Build(),
	}

	repository := data.MariaDbRepository{
		SqlDb: dbConnector,
	}

	// set up indexer
	hmacSecret, err := base64.StdEncoding.DecodeString(os.Getenv(EnvDbIndexHmac))
	if err != nil {
		log.Fatalf("unable to decode hmac key Env var: %v", err)
	}
	indexer := data.NewHmacIndexer(hmacSecret)

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(os.Getenv(EnvFieldsKey))
	if err != nil {
		log.Panicf("unable to decode field level encryption key Env var: %v", err)
	}

	// set up s2s jwt verifier
	pubPem, err := base64.StdEncoding.DecodeString(os.Getenv(EnvS2sJwtVerifyKey))
	if err != nil {
		log.Panicf("unable to (base64) decode jwt-verifying public key: %v", err)
	}
	pubBlock, _ := pem.Decode(pubPem)
	genericPublicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		log.Panicf("unable to parse pub Block to generic public key: %v", err)
	}
	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Panic("Not an ECDSA public key")
	}
	jwtVerifier := jwt.JwtVerifierService{
		PublicKey: publicKey,
	}

	// s2s creds
	s2sCmd := session.S2sLoginCmd{
		ClientId:     os.Getenv(EnvClientId),
		ClientSecret: os.Getenv(EnvClientSecret),
	}

	s2sProvider := session.S2sTokenProvider{
		S2sServiceUrl: os.Getenv(EnvS2sTokenUrl),
		Credentials:   s2sCmd,
		S2sClient:     client,
		Dao:           &repository,
	}

	// set up signer
	// privPem, err := base64.StdEncoding.DecodeString(os.Getenv(EnvJwtSigningKey))
	// if err != nil {
	// 	log.Fatalf("unable to decode (base64) signing key Env var: %v", err)
	// }
	// privBlock, _ := pem.Decode(privPem)
	// privateKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	// if err != nil {
	// 	log.Fatalf("unable to parse x509 EC Private Key: %v", err)
	// }
	// signer := jwt.JwtSignerService{PrivateKey: privateKey}

	// registration service + handler

}
