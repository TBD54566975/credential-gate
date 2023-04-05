package gate

import (
	"github.com/TBD54566975/ssi-sdk/credential"
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

	r, err := resolver.NewResolver([]string{"key", "web", "pkh", "peer"}, config.UniversalResolverURL)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "failed to create resolver")
	}

	return &CredentialGate{
		resolver: r,
		config:   config,
	}, nil
}

// Presentation is a struct that contains sets of VPs and/or VP JWTs, both of which can be used
// that are to be validated against the credential gate's presentation definition
type Presentation struct {
	VerifiablePresentation    *credential.VerifiablePresentation `json:"presentation,omitempty"`
	VerifiablePresentationJWT *string                            `json:"presentationJwt,omitempty"`
}

func (p Presentation) IsValid() bool {
	bothEmpty := p.VerifiablePresentation.IsEmpty() && p.VerifiablePresentationJWT == nil
	bothPresent := !p.VerifiablePresentation.IsEmpty() && p.VerifiablePresentationJWT != nil
	return !bothEmpty && !bothPresent
}

func (cg *CredentialGate) ValidatePresentation(presentation Presentation) (bool, error) {
	if !presentation.IsValid() {
		return false, util.LoggingErrorMsg(nil, "invalid presentation")
	}

	// handle having a VP
	if !presentation.VerifiablePresentation.IsEmpty() {
		return false, util.LoggingErrorMsg(nil, "Linked Data VP not yet supported")
	}

	// handle having a VP JWT
	if presentation.VerifiablePresentationJWT != nil {
		vpJWT, err := signing.ParseVerifiablePresentationFromJWT(*presentation.VerifiablePresentationJWT)
		if err != nil {
			return false, util.LoggingErrorMsg(err, "failed to parse VP JWT")
		}
		vp = *vpJWT
	}

	return false, nil
}
