package gate

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type CustomHandlerLogic func(ctx context.Context, vsd exchange.VerifiedSubmissionData) (bool, error)

type CustomHandler struct {
	InputDescriptorID string             `json:"inputDescriptorId" validate:"required"`
	Handler           CustomHandlerLogic `json:"customHandlerLogic" validate:"required"`
}

// applyCustomHandlers applies the custom handlers to the verified submission data
// not all submission data will have a custom handler associated with it
// we process as follows:
// 1. for each custom handler, get the input descriptor ID
// 2. for each input descriptor ID, find the corresponding submission data (if missing, fail)
// 3. for each submission data, apply the custom handler
// 4. if any custom handler fails, return false
func (cg *CredentialGate) applyCustomHandlers(ctx context.Context, verifiedSubmissionData []exchange.VerifiedSubmissionData) (bool, error) {
	submissionDataMap := make(map[string]exchange.VerifiedSubmissionData)
	for _, sd := range verifiedSubmissionData {
		if _, ok := submissionDataMap[sd.InputDescriptorID]; ok {
			// TODO(gabe) handle the case where there are multiple credentials that fulfill a single input descriptor
			return false, errors.Errorf("duplicate submission data for input descriptor ID %s", sd.InputDescriptorID)
		}
		submissionDataMap[sd.InputDescriptorID] = sd
	}

	for _, ch := range cg.config.CustomHandlers {
		sd, ok := submissionDataMap[ch.InputDescriptorID]
		if !ok {
			return false, errors.Errorf("missing submission data for input descriptor ID %s", ch.InputDescriptorID)
		}
		handled, err := ch.Handler(ctx, sd)
		if err != nil {
			return false, util.LoggingErrorMsg(err, "running custom handler")
		}
		if !handled {
			logrus.Errorf("custom handler failed for input descriptor ID %s", ch.InputDescriptorID)
			return false, nil
		}
	}
	return true, nil
}
