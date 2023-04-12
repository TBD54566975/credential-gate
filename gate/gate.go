package gate

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/pkg/errors"

	"github.com/TBD54566975/credential-gate/resolver"
)

type CredentialGateConfig struct {
	// TODO(gabe) allow configuration of supported DID methods https://github.com/TBD54566975/credential-gate/issues/7
	// SupportedDIDMethods is a list of DID methods that are supported by this credential gate
	// If empty, all DID methods are supported
	// SupportedDIDMethods []didsdk.Method `json:"supportedDidMethods,omitempty"`

	// UniversalResolverURL is the URL of the universal resolver to use for resolving DIDs
	// If empty, a universal resolver will not be configured
	UniversalResolverURL string `json:"universalResolverUrl,omitempty"`

	// PresentationDefinition is the presentation definition that this credential gate will
	// use to validate credentials against
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition" validate:"required"`

	// TODO(gabe) custom credential handler logic https://github.com/TBD54566975/credential-gate/issues/4
}

func (c CredentialGateConfig) IsValid() error {
	if err := util.IsValidStruct(c); err != nil {
		return errors.Wrap(err, "invalid config struct")
	}
	if err := c.PresentationDefinition.IsValid(); err != nil {
		return errors.Wrap(err, "invalid presentation definition")
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

func (cg *CredentialGate) ValidatePresentationSubmission(presentationSubmissionJWT string) (bool, error) {
	// extract the VP signer's DID, which is set as the iss property as per https://w3c.github.io/vc-jwt/#vp-jwt-1.1
	headers, token, vp, err := signing.ParseVerifiablePresentationFromJWT(presentationSubmissionJWT)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "parsing VP from JWT")
	}
	if vp.PresentationSubmission == nil {
		// TODO(gabe): in-place build a presentation submission from the VP https://github.com/TBD54566975/credential-gate/issues/5
		return false, util.LoggingErrorMsg(err, "no presentation submission found in VP")
	}

	issuer := token.Issuer()
	maybeKID, ok := headers.Get(jws.KeyIDKey)
	if !ok {
		return false, util.LoggingErrorMsg(err, "getting kid from VP JWT")
	}
	kid, ok := maybeKID.(string)
	if !ok {
		return false, util.LoggingErrorMsg(err, "casting kid to string")
	}

	// resolve the VP signer's DID
	did, err := cg.resolver.Resolve(context.Background(), issuer)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "resolving VP submission signer's DID")
	}
	pubKey, err := didsdk.GetKeyFromVerificationMethod(did.Document, kid)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "getting public key from VP signer's DID")
	}

	// verify the presentation submission
	verifier, err := crypto.NewJWTVerifier(did.ID, kid, pubKey)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "constructing JWT verifier")
	}
	if err = exchange.VerifyPresentationSubmission(*verifier, exchange.JWTVPTarget, cg.config.PresentationDefinition,
		[]byte(presentationSubmissionJWT)); err != nil {
		return false, util.LoggingErrorMsg(err, "verifying presentation submission")
	}

	return true, nil
}
