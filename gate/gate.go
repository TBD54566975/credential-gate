package gate

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/credential-gate/resolver"
)

type CredentialGateConfig struct {
	// TODO(gabe) allow configuration of supported DID methods https://github.com/TBD54566975/credential-gate/issues/7
	// SupportedDIDMethods is a list of DID methods that are supported by this credential gate
	// If empty, all DID methods are supported
	// SupportedDIDMethods []didsdk.Method `json:"supportedDidMethods,omitempty"`

	// AdminDID is the DID of the credential gate; the audience of any presentation submission
	// submitted to the gate.
	AdminDID string `json:"adminDid" validate:"required"`

	// UniversalResolverURL is the URL of the universal resolver to use for resolving DIDs
	// If empty, a universal resolver will not be configured
	UniversalResolverURL string `json:"universalResolverUrl,omitempty"`

	// PresentationDefinition is the presentation definition that this credential gate will
	// use to validate credentials against
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition" validate:"required"`

	// CustomHandlers is a list of custom handlers that can be used to validate credentials
	CustomHandlers map[string]CustomHandler `json:"customHandlers,omitempty"`
}

func (c CredentialGateConfig) IsValid() error {
	if err := util.IsValidStruct(c); err != nil {
		return errors.Wrap(err, "invalid config struct")
	}
	if err := c.PresentationDefinition.IsValid(); err != nil {
		return errors.Wrap(err, "invalid presentation definition")
	}
	for id, ch := range c.CustomHandlers {
		if id != ch.InputDescriptorID {
			return errors.Errorf("mismatched input descriptor ID, expected: %s, got %s", id, ch.InputDescriptorID)
		}
		if err := util.IsValidStruct(ch); err != nil {
			return errors.Wrap(err, "invalid custom handler")
		}
	}
	return nil
}

type CredentialGate struct {
	resolver *resolver.Resolver
	config   CredentialGateConfig
}

// NewCredentialGate creates a new CredentialGate instance using the given config
// which is used to validate credentials against the given presentation definition
func NewCredentialGate(config CredentialGateConfig) (*CredentialGate, error) {
	if err := config.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "invalid config")
	}

	r, err := resolver.NewResolver(localResolverMethods(), config.UniversalResolverURL)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "failed to create resolver")
	}

	return &CredentialGate{
		resolver: r,
		config:   config,
	}, nil
}

func localResolverMethods() []didsdk.Method {
	return []didsdk.Method{didsdk.KeyMethod, didsdk.WebMethod, didsdk.PKHMethod, didsdk.PeerMethod}
}

type Result struct {
	Valid        bool   `json:"valid,omitempty"`
	SubmissionID string `json:"submissionId,omitempty"`
	Submitter    string `json:"submitter,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func (cg *CredentialGate) ValidatePresentationSubmission(ctx context.Context, presentationSubmissionJWT string) (*Result, error) {
	// extract the VP signer's DID, which is set as the iss property as per https://w3c.github.io/vc-jwt/#vp-jwt-1.1
	headers, token, vp, err := credential.ParseVerifiablePresentationFromJWT(presentationSubmissionJWT)
	if err != nil {
		return &Result{Valid: false}, util.LoggingErrorMsg(err, "parsing VP from JWT")
	}
	issuer := token.Issuer()
	id := token.JwtID()
	gateResult := &Result{Valid: false, SubmissionID: id, Submitter: issuer}
	if vp.PresentationSubmission == nil {
		// TODO(gabe): in-place build a presentation submission from the VP https://github.com/TBD54566975/credential-gate/issues/5
		return gateResult, util.LoggingErrorMsg(err, "no presentation submission found in VP")
	}

	maybeKID, ok := headers.Get(jws.KeyIDKey)
	if !ok {
		return gateResult, util.LoggingErrorMsg(err, "getting kid from VP JWT")
	}
	kid, ok := maybeKID.(string)
	if !ok {
		return gateResult, util.LoggingErrorMsg(err, "casting kid to string")
	}

	// resolve the VP signer's DID
	did, err := cg.resolver.Resolve(ctx, issuer)
	if err != nil {
		return gateResult, util.LoggingErrorMsg(err, "resolving VP submission signer's DID")
	}
	pubKey, err := didsdk.GetKeyFromVerificationMethod(did.Document, kid)
	if err != nil {
		return gateResult, util.LoggingErrorMsg(err, "getting public key from VP signer's DID")
	}

	// verify the presentation submission and extract the submission data
	// the admin DID is set as the audience for the verifier
	verifier, err := crypto.NewJWTVerifier(cg.config.AdminDID, pubKey)
	if err != nil {
		return gateResult, util.LoggingErrorMsg(err, "constructing JWT verifier")
	}
	verifiedSubmissionData, err := exchange.VerifyPresentationSubmission(ctx, *verifier, cg.resolver, exchange.JWTVPTarget, cg.config.PresentationDefinition,
		[]byte(presentationSubmissionJWT))
	if err != nil {
		gateResult.Reason = err.Error()
		return gateResult, util.LoggingErrorMsg(err, "verifying presentation submission")
	}

	// validate the presentation submission with custom handlers
	handled, err := cg.applyCustomHandlers(ctx, verifiedSubmissionData)
	if err != nil {
		gateResult.Reason = err.Error()
		return gateResult, util.LoggingErrorMsg(err, "applying custom handlers")
	}
	gateResult.Valid = handled
	return gateResult, nil
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
		submissionDataMap[sd.InputDescriptorID] = sd
	}

	for _, ch := range cg.config.CustomHandlers {
		sd, ok := submissionDataMap[ch.InputDescriptorID]
		if !ok {
			return false, errors.Errorf("missing submission data for input descriptor ID %s", ch.InputDescriptorID)
		}
		handled, err := ch.Handle(ctx, sd)
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
