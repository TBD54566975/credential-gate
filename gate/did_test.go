package gate

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
)

func TestGetKeyFromVerificationInformation(t *testing.T) {
	t.Run("empty doc", func(tt *testing.T) {
		_, err := GetKeyFromVerificationInformation(did.Document{}, "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "did doc cannot be empty")
	})

	t.Run("doc with no verification methods", func(t *testing.T) {
		doc := did.Document{ID: "test-did"}
		_, err := GetKeyFromVerificationInformation(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has no verification methods")
	})

	t.Run("doc without specified kid", func(t *testing.T) {
		doc := did.Document{
			ID: "test-did",
			VerificationMethod: []did.VerificationMethod{
				{
					ID:              "#test-kid-2",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: "test-key",
				},
			},
		}
		_, err := GetKeyFromVerificationInformation(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no verification methods with kid: test-kid")
	})

	t.Run("doc with specified kid, bad multibase key", func(t *testing.T) {
		doc := did.Document{
			ID: "test-did",
			VerificationMethod: []did.VerificationMethod{
				{
					ID:                 "#test-kid",
					Type:               "Ed25519VerificationKey2018",
					PublicKeyMultibase: "test-key",
				},
			},
		}
		_, err := GetKeyFromVerificationInformation(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "converting multibase key")
	})

	t.Run("doc with specified kid, bad b58 key", func(t *testing.T) {
		doc := did.Document{
			ID: "test-did",
			VerificationMethod: []did.VerificationMethod{
				{
					ID:              "#test-kid",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: "test-key",
				},
			},
		}
		_, err := GetKeyFromVerificationInformation(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding base58 key")
	})

	t.Run("doc with specified kid, bad JWK key", func(t *testing.T) {
		doc := did.Document{
			ID: "test-did",
			VerificationMethod: []did.VerificationMethod{
				{
					ID:   "#test-kid",
					Type: "Ed25519VerificationKey2018",
					PublicKeyJWK: &crypto.PublicKeyJWK{
						KID: "bad",
					},
				},
			},
		}
		_, err := GetKeyFromVerificationInformation(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parsing jwk")
	})

	t.Run("doc with specified kid, bad pub key", func(t *testing.T) {

	})

}
