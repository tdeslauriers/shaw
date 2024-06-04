package authentication

import (
	"log/slog"
	"net/http"
	"shaw/internal/util"

	"github.com/tdeslauriers/carapace/pkg/session"
)

type LoginHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewLoginHandler(service session.UserAuthService) LoginHandler {
	return &loginHandler{
		authService: service,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	authService session.UserAuthService

	logger *slog.Logger
}

func (h *loginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

}
