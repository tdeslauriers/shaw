package identity

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"
	"shaw/pkg/register"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type Identity interface {
	Run() error
	CloseDb() error
}

func New(config config.Config) (Identity, error) {

	// server
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
		CaFiles:  []string{*config.Certs.ServerCa},
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(config.Tls, serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure server tls: %v", err)
	}

	// identity service client
	clientPki := &connect.Pki{
		CertFile: *config.Certs.ClientCert,
		KeyFile:  *config.Certs.ClientKey,
		CaFiles:  []string{*config.Certs.ClientCa},
	}

	clientConfig := connect.NewTlsClientConfig(clientPki)
	client, err := connect.NewTlsClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure s2s client config: %v", err)
	}

	// db client
	dbClientPki := &connect.Pki{
		CertFile: *config.Certs.DbClientCert,
		KeyFile:  *config.Certs.DbClientKey,
		CaFiles:  []string{*config.Certs.DbCaCert},
	}

	dbClientConfig, err := connect.NewTlsClientConfig(dbClientPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure database client tls: %v", err)
	}

	// db config
	dbUrl := data.DbUrl{
		Name:     config.Database.Name,
		Addr:     config.Database.Url,
		Username: config.Database.Username,
		Password: config.Database.Password,
	}

	db, err := data.NewSqlDbConnector(dbUrl, dbClientConfig).Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	repository := data.NewSqlRepository(db)

	// indexer
	hmacSecret, err := base64.StdEncoding.DecodeString(config.Database.IndexSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hmac key: %v", err)
	}

	indexer := data.NewIndexer(hmacSecret)

	// field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// s2s jwt verifier
	// format public key for use in jwt verification
	pubPem, err := base64.StdEncoding.DecodeString(config.Jwt.S2sVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode s2s jwt-verifying public key: %v", err)
	}
	pubBlock, _ := pem.Decode(pubPem)
	genericPublicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub Block to generic public key: %v", err)
	}
	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	s2sVerifier := jwt.NewJwtVerifier(config.Name, publicKey)

	// retry config for s2s callers
	retry := connect.RetryConfiguration{
		MaxRetries:  5,
		BaseBackoff: 100 * time.Microsecond,
		MaxBackoff:  10 * time.Second,
	}

	// s2s caller
	s2sCaller := connect.NewS2sCaller(config.ServiceAuth.Url, util.S2sServiceName, client, retry)

	// s2s token provider
	s2sCreds := session.S2sCredentials{
		ClientId:     config.ServiceAuth.ClientId,
		ClientSecret: config.ServiceAuth.ClientSecret,
	}

	s2sProvider := session.NewS2sTokenProvider(s2sCaller, s2sCreds, repository, cryptor)

	// user jwt signer
	privPem, err := base64.StdEncoding.DecodeString(config.Jwt.UserSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user jwt-signing key: %v", err)
	}
	privBlock, _ := pem.Decode(privPem)
	privateKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse priv Block to private key: %v", err)
	}

	signer := jwt.NewJwtSigner(privateKey)

	// user jwt verifier
	//TODO: implement user jwt verifier

	// registration service
	regService := register.NewRegistrationService(repository, cryptor, indexer, s2sProvider, s2sCaller)

	// auth service
	authService := authentication.NewUserAuthService(repository, signer, indexer, cryptor)

	// oauth flow service
	oathFlowService := authentication.NewOauthFlowService(repository, cryptor, indexer, s2sProvider, s2sCaller)

	// refresh service
	// TODO: implement refresh service

	// password change service
	// TODO: implement password change service

	return &identity{
		config:          config,
		serverTls:       serverTlsConfig,
		repository:      repository,
		s2sVerifier:     s2sVerifier,
		registerService: regService,
		authService:     authService,
		oathFlowService: oathFlowService,
		// refresh service
		// password change service

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentIdentity)),
	}, nil
}

var _ Identity = (*identity)(nil)

type identity struct {
	config          config.Config
	serverTls       *tls.Config
	repository      data.SqlRepository
	s2sVerifier     jwt.JwtVerifier
	registerService register.RegistrationService
	authService     session.UserAuthService
	oathFlowService authentication.OauthFlowService
	// refresh service
	// password change service

	logger *slog.Logger
}

func (i *identity) CloseDb() error {
	if err := i.repository.Close(); err != nil {
		return err
	}
	return nil
}

func (i *identity) Run() error {

	// register handlers
	regHander := register.NewRegistrationHandler(i.registerService, i.s2sVerifier)

	// login handler
	loginHandler := authentication.NewLoginHandler(i.authService, i.oathFlowService, i.s2sVerifier)

	// oauth callback handler
	// TODO: implement oauth callback handler

	// refresh handler
	// TODO: implement refresh handler

	// password change handler
	// TODO: implement password change handler

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/register", regHander.HandleRegistration)
	mux.HandleFunc("/login", loginHandler.HandleLogin)

	identityServer := &connect.TlsServer{
		Addr:      ":8445",
		Mux:       mux,
		TlsConfig: i.serverTls,
	}

	go func() {
		i.logger.Info(fmt.Sprintf("starting %s service on port %s...", i.config.Name, identityServer.Addr[1:]))
		if err := identityServer.Initialize(); err != http.ErrServerClosed {
			i.logger.Error(fmt.Sprintf("failed to start %s user authentication service", i.config.Name), "err", err.Error())
		}
	}()

	return nil
}
