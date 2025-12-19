package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/shaw/internal/identity"
	"github.com/tdeslauriers/shaw/internal/util"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	// set default logger for all packages to use json format
	slog.SetDefault(slog.New(jsonHandler).
		With(slog.String(util.ServiceKey, util.ServiceIdentity)))

	// set up logger for main
	logger := slog.Default().
		With(slog.String(util.PackageKey, util.PackageMain)).
		With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definition
	def := config.SvcDefinition{
		ServiceName: util.ServiceIdentity,
		Tls:         config.MutualTls,
		Requires: config.Requires{
			S2sClient:        true,
			Db:               true,
			IndexSecret:      true,
			AesSecret:        true,
			S2sSigningKey:    false,
			S2sVerifyingKey:  true,
			Identity:         false, // identity service does not require itself
			UserSigningKey:   true,
			UserVerifyingKey: false,
			OauthRedirect:    false,
		},
	}

	// load env vars
	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to load %s identity service config", def.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	identity, err := identity.New(*config)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s identity service", config.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	defer identity.CloseDb()

	if err := identity.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s identity service", config.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	select {}
}
