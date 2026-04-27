package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tdeslauriers/carapace/pkg/config"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"github.com/tdeslauriers/shaw/internal/identity"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := identity.Run(ctx); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s identity service", config.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	<-ctx.Done()
}
