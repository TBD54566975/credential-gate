package gate

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
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
