package identity

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"
	"shaw/pkg/callback"
	"shaw/pkg/login"
	"shaw/pkg/oauth"
	"shaw/pkg/refresh"
	"shaw/pkg/register"
	"shaw/pkg/user"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/schedule"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/sign"
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
		return nil, fmt.Errorf("failed to decode hmac secret: %v", err)
	}

	indexer := data.NewIndexer(hmacSecret)

	// field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption secret: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// retry config for s2s callers
	retry := connect.RetryConfiguration{
		MaxRetries:  5,
		BaseBackoff: 100 * time.Microsecond,
		MaxBackoff:  10 * time.Second,
	}

	// s2s caller
	s2sCaller := connect.NewS2sCaller(config.ServiceAuth.Url, util.ServiceNameS2s, client, retry)

	// s2s token provider
	s2sCreds := provider.S2sCredentials{
		ClientId:     config.ServiceAuth.ClientId,
		ClientSecret: config.ServiceAuth.ClientSecret,
	}

	s2sProvider := provider.NewS2sTokenProvider(s2sCaller, s2sCreds, repository, cryptor)

	// s2s jwt verifing key
	s2sPublicKey, err := sign.ParsePublicEcdsaCert(config.Jwt.S2sVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse s2s jwt verifying key: %v", err)
	}

	// user jwt signer
	iamPrivateKey, err := sign.ParsePrivateEcdsaCert(config.Jwt.UserSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user jwt signing key: %v", err)
	}

	// identity jwt signer
	iamSigner := jwt.NewSigner(iamPrivateKey)

	return &identity{
		config:          config,
		serverTls:       serverTlsConfig,
		repository:      repository,
		s2sVerifier:     jwt.NewVerifier(config.ServiceName, s2sPublicKey),
		iamVerifier:     jwt.NewVerifier(config.ServiceName, &iamPrivateKey.PublicKey),
		authService:     authentication.NewService(repository, iamSigner, indexer, cryptor, s2sProvider, s2sCaller),
		oathService:     oauth.NewService(repository, indexer, cryptor),
		registerService: register.NewService(repository, cryptor, indexer, s2sProvider, s2sCaller),
		userService:     user.NewService(repository, indexer, cryptor, s2sProvider, s2sCaller),
		cleanup:         schedule.NewCleanup(repository),

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentIdentity)),
	}, nil
}

var _ Identity = (*identity)(nil)

type identity struct {
	config          config.Config
	serverTls       *tls.Config
	repository      data.SqlRepository
	s2sVerifier     jwt.Verifier
	iamVerifier     jwt.Verifier
	authService     authentication.Service
	oathService     oauth.Service
	registerService register.Service
	userService     user.Service
	cleanup         schedule.Cleanup

	logger *slog.Logger
}

func (i *identity) CloseDb() error {
	if err := i.repository.Close(); err != nil {
		return err
	}
	return nil
}

func (i *identity) Run() error {

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	registerHandler := register.NewHandler(i.registerService, i.s2sVerifier)
	mux.HandleFunc("/register", registerHandler.HandleRegistration)

	loginHandler := login.NewHandler(i.authService, i.oathService, i.s2sVerifier)
	mux.HandleFunc("/login", loginHandler.HandleLogin)

	callbackHandler := callback.NewHandler(i.s2sVerifier, i.authService, i.oathService)
	mux.HandleFunc("/callback", callbackHandler.HandleCallback)

	refreshHandler := refresh.NewHandler(i.authService, i.s2sVerifier, i.userService)
	mux.HandleFunc("/refresh", refreshHandler.HandleRefresh)
	mux.HandleFunc("/refresh/destroy", refreshHandler.HandleDestroy)

	// users endpoints for s2s clients (not user facing)
	// requires s2s service-call-specific scopes
	s2sUserHandler := user.NewHandler(i.userService, i.s2sVerifier, nil)
	mux.HandleFunc("/s2s/users", s2sUserHandler.HandleUsers)
	mux.HandleFunc("/s2s/users/", s2sUserHandler.HandleUser)
	mux.HandleFunc("/s2s/users/groups", s2sUserHandler.HandleUserGroups)

	userHandler := user.NewHandler(i.userService, i.s2sVerifier, i.iamVerifier)
	mux.HandleFunc("/profile", userHandler.HandleProfile)
	mux.HandleFunc("/reset", userHandler.HandleReset)
	mux.HandleFunc("/users", userHandler.HandleUsers)
	mux.HandleFunc("/users/", userHandler.HandleUser)
	mux.HandleFunc("/users/scopes", userHandler.HandleScopes)

	identityServer := &connect.TlsServer{
		Addr:      i.config.ServicePort,
		Mux:       mux,
		TlsConfig: i.serverTls,
	}

	go func() {
		i.logger.Info(fmt.Sprintf("starting %s service on port %s...", i.config.ServiceName, identityServer.Addr[1:]))
		if err := identityServer.Initialize(); err != http.ErrServerClosed {
			i.logger.Error(fmt.Sprintf("failed to start %s user authentication service", i.config.ServiceName), "err", err.Error())
		}
	}()

	i.cleanup.ExpiredRefresh(12)
	i.cleanup.ExpiredAuthcode()
	i.cleanup.ExpiredS2s()

	return nil
}
