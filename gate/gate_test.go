package gate

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCredentialGateConfig(t *testing.T) {
	t.Run("bad config", func(tt *testing.T) {
		_, err := NewCredentialGate(CredentialGateConfig{})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid config")
	})

	t.Run("bad presentation definition in config", func(tt *testing.T) {
		_, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: exchange.PresentationDefinition{
				ID: "test",
				InputDescriptors: []exchange.InputDescriptor{
					{
						ID:          "test",
						Constraints: &exchange.Constraints{},
					},
				},
			},
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid presentation definition")
	})

	t.Run("good config", func(tt *testing.T) {
		simplePresentationDefinition := exchange.PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []exchange.InputDescriptor{
				{
					ID: uuid.New().String(),
					Constraints: &exchange.Constraints{
						Fields: []exchange.Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer is known",
								Filter: &exchange.Filter{
									Type:    "string",
									Pattern: "known-issuer",
								},
							},
						},
					},
				},
			},
		}
		gate, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: simplePresentationDefinition,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gate)
	})
}

func TestCredentialGate(t *testing.T) {

}
