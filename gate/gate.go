package gate

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"

	"github.com/TBD54566975/credential-gate/resolver"
)

type CredentialGateConfig struct {
}

type CredentialGate struct {
	resolver               *resolver.Resolver
	presentationDefinition *exchange.PresentationDefinition
}

func NewCredentialGate(config CredentialGateConfig) (*CredentialGate, error) {
	return &CredentialGate{}, nil
}
