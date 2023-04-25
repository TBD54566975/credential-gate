package gate

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
)

type CustomHandlerLogic func(ctx context.Context, vsd exchange.VerifiedSubmissionData) (bool, error)

type CustomHandler struct {
	InputDescriptorID string             `json:"inputDescriptorId" validate:"required"`
	Handle            CustomHandlerLogic `json:"customHandlerLogic" validate:"required"`
}
