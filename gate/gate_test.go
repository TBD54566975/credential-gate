package gate

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

// TestMain is used to set up schema caching in order to load all schemas locally
func TestMain(m *testing.M) {
	localSchemas, err := schema.GetAllLocalSchemas()
	if err != nil {
		os.Exit(1)
	}
	loader, err := schema.NewCachingLoader(localSchemas)
	if err != nil {
		os.Exit(1)
	}
	loader.EnableHTTPCache()
	os.Exit(m.Run())
}

func TestCredentialGateConfig(t *testing.T) {
	validPresentationDefinition := exchange.PresentationDefinition{
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
		gate, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: validPresentationDefinition,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gate)
	})

	t.Run("good config - bad resolver", func(tt *testing.T) {
		_, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: validPresentationDefinition,
			UniversalResolverURL:   "bad",
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "failed to create resolver")
	})

	t.Run("good config - good resolver", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/methods").
			Reply(200)

		gate, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: validPresentationDefinition,
			UniversalResolverURL:   "https://dev.uniresolver.io",
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gate)
	})
}

func TestCredentialGate(t *testing.T) {

}
