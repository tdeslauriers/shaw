package main

import (
	"fmt"
	"log/slog"
	"os"
	"shaw/internal/util"
	"shaw/pkg/identity"

	"github.com/tdeslauriers/carapace/pkg/config"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(jsonHandler))

	// set up logger for main
	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definition
	def := config.SvcDefinition{
		ServiceName: "shaw",
		Tls:         config.MutualTls,
		Requires: config.Requires{
			S2sClient:        true,
			Db:               true,
			IndexKey:         true,
			AesKey:           true,
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
