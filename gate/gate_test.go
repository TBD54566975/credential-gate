package gate

import (
	"os"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
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
			Reply(200).
			BodyString(`["web"]`)

		gate, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: validPresentationDefinition,
			UniversalResolverURL:   "https://dev.uniresolver.io",
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gate)
	})
}

func TestCredentialGate(t *testing.T) {
	t.Run("jwt but not a presentation submission", func(tt *testing.T) {
		presentationDefinition := exchange.PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []exchange.InputDescriptor{
				{
					ID: uuid.New().String(),
					Format: &exchange.ClaimFormat{
						JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
					},
					Constraints: &exchange.Constraints{
						Fields: []exchange.Field{
							{
								Path: []string{"$.iss"},
							},
						},
					},
				},
			},
		}
		gate, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: presentationDefinition,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gate)

		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)
		assert.NotEmpty(tt, didKey)

		// signer for the submission
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		signer, err := crypto.NewJWTSigner(didKey.String(), expanded.VerificationMethod[0].ID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signer)

		// self sign a credential for the submission
		testCredential := credential.VerifiableCredential{
			Context:      []any{"https://www.w3.org/2018/credentials/v1"},
			Type:         []string{"VerifiableCredential"},
			Issuer:       didKey.String(),
			IssuanceDate: time.Now().Format(time.RFC3339),
			CredentialSubject: map[string]any{
				"id": didKey.String(),
			},
		}
		testVCJWT, err := signing.SignVerifiableCredentialJWT(*signer, testCredential)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, testVCJWT)

		result, err := gate.ValidatePresentationSubmission(string(testVCJWT))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "parsing VP from JWT")
		assert.False(tt, result.Valid)
	})

	t.Run("happy path - accept any valid JWT VP, EdDSA, with a credential subject", func(tt *testing.T) {
		requesterID := "requester"
		presentationDefinition := exchange.PresentationDefinition{
			ID: uuid.New().String(),
			Format: &exchange.ClaimFormat{
				JWTVP: &exchange.JWTType{
					Alg: []crypto.SignatureAlgorithm{crypto.EdDSA},
				},
			},
			InputDescriptors: []exchange.InputDescriptor{
				{
					ID: uuid.New().String(),
					Format: &exchange.ClaimFormat{
						JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
					},
					Constraints: &exchange.Constraints{
						Fields: []exchange.Field{
							{
								Path: []string{"$.vc.credentialSubject.name"},
								Filter: &exchange.Filter{
									Type:    "string",
									Pattern: "Satoshi",
								},
							},
						},
					},
				},
			},
		}
		gate, err := NewCredentialGate(CredentialGateConfig{
			PresentationDefinition: presentationDefinition,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gate)

		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)
		assert.NotEmpty(tt, didKey)

		// signer for the submission
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		signer, err := crypto.NewJWTSigner(didKey.String(), expanded.VerificationMethod[0].ID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signer)

		// self sign a credential for the submission
		testCredential := credential.VerifiableCredential{
			Context:      []any{"https://www.w3.org/2018/credentials/v1"},
			Type:         []string{"VerifiableCredential"},
			Issuer:       didKey.String(),
			IssuanceDate: time.Now().Format(time.RFC3339),
			CredentialSubject: map[string]any{
				"id":   didKey.String(),
				"name": "Satoshi",
			},
		}
		testVCJWT, err := signing.SignVerifiableCredentialJWT(*signer, testCredential)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, testVCJWT)
		presentationClaimJWT := exchange.PresentationClaim{
			TokenBytes:                    testVCJWT,
			JWTFormat:                     exchange.JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		}

		// build a presentation submission to match
		submissionJWT, err := exchange.BuildPresentationSubmission(*signer, requesterID,
			presentationDefinition, []exchange.PresentationClaim{presentationClaimJWT}, exchange.JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionJWT)

		result, err := gate.ValidatePresentationSubmission(string(submissionJWT))
		assert.NoError(tt, err)
		assert.True(tt, result.Valid)
	})
}
