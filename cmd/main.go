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

	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definition
	def := config.SvcDefinition{
		Name: "shaw",
		Tls:  config.MutualTls,
		Requires: config.Requires{
			Client:           true,
			Db:               true,
			IndexKey:         true,
			AesKey:           true,
			UserAuthUrl:      false,
			S2sSigningKey:    false,
			S2sVerifyingKey:  true,
			UserSigningKey:   true,
			UserVerifyingKey: false,
		},
	}

	// load env vars
	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to load %s identity service config", def.Name), "err", err.Error())
		os.Exit(1)
	}

	identity, err := identity.New(*config)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s identity service", config.Name), "err", err.Error())
		os.Exit(1)
	}

	defer identity.CloseDb()

	if err := identity.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s identity service", config.Name), "err", err.Error())
		os.Exit(1)
	}

	select {}
}
