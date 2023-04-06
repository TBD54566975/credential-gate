package gate

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"

	"github.com/TBD54566975/credential-gate/resolver"
)

type CredentialGateConfig struct {
	// SupportedDIDMethods is a list of DID methods that are supported by this credential gate
	// If empty, all DID methods are supported
	SupportedDIDMethods []didsdk.Method `json:"supportedDidMethods,omitempty"`

	// UniversalResolverURL is the URL of the universal resolver to use for resolving DIDs
	// If empty, a universal resolver will not be configured
	UniversalResolverURL string `json:"universalResolverUrl,omitempty"`

	// PresentationDefinition is the presentation definition that this credential gate will
	// use to validate credentials against
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition" validate:"required"`
}

type CredentialGate struct {
	resolver *resolver.Resolver
	config   CredentialGateConfig
}

// NewCredentialGate creates a new CredentialGate instance using the given config
// which is used to validate credentials against the given presentation definition
func NewCredentialGate(config CredentialGateConfig) (*CredentialGate, error) {
	if err := util.IsValidStruct(config); err != nil {
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

func (cg *CredentialGate) ValidatePresentation(presentationJWT string) (bool, error) {
	// extract the VP signer's DID, which is set as the iss property as per https://w3c.github.io/vc-jwt/#vp-jwt-1.1

	// extract the VP signer's KID from the JWT header
	// the KID could be fully qualified, or just the key id, so we need to resolve the DID to get the full KID
	// and search for the key in the DID document by both the full KID and the key id

	// construct a verifier after resolving the VP signer's DID

	// verify the VP JWT's signature
	if _, err := signing.VerifyVerifiablePresentationJWT(verifier, presentationJWT); err != nil {
		return false, util.LoggingErrorMsg(err, "failed to verify VP JWT")
	}

	// validate the VP against the presentation definition
	presentation, err := signing.ParseVerifiablePresentationFromJWT(presentationJWT)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "failed to parse VP from JWT")
	}

	return false, nil
}
