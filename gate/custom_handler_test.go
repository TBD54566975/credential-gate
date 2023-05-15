package gate

import (
	"context"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestCustomHandler(t *testing.T) {
	requesterID := "did:test:admin"
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
							Path: []string{"$.vc.credentialSubject.invalidAfter"},
						},
					},
				},
			},
		},
	}

	t.Run("Test Custom Expiration Handler - Bad input descriptor id for handler", func(tt *testing.T) {
		// add new custom handler with a valid input descriptor ID
		_, err := NewCredentialGate(CredentialGateConfig{
			AdminDID:               requesterID,
			PresentationDefinition: presentationDefinition,
			CustomHandlers: map[string]CustomHandler{
				presentationDefinition.ID: newInvalidAfterHandler(presentationDefinition.InputDescriptors[0].ID),
			},
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "mismatched input descriptor ID")
	})

	t.Run("Test Custom Expiration Handler - no input descriptors match handler", func(tt *testing.T) {
		// add new custom handler with a valid input descriptor ID
		_, err := NewCredentialGate(CredentialGateConfig{
			AdminDID:               requesterID,
			PresentationDefinition: presentationDefinition,
			CustomHandlers: map[string]CustomHandler{
				"bad": newInvalidAfterHandler("bad"),
			},
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "input descriptor ID bad not found in presentation definition")
	})

	t.Run("Test Expiration Handler - Expired cred", func(tt *testing.T) {
		// add new custom handler with a valid input descriptor ID
		inputDescriptorID := presentationDefinition.InputDescriptors[0].ID
		gate, err := NewCredentialGate(CredentialGateConfig{
			AdminDID:               requesterID,
			PresentationDefinition: presentationDefinition,
			CustomHandlers: map[string]CustomHandler{
				inputDescriptorID: newInvalidAfterHandler(inputDescriptorID),
			},
		})
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)

		// signer for the submission
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)

		signer, err := jwx.NewJWXSigner(didKey.String(), expanded.VerificationMethod[0].ID, privKey)
		assert.NoError(tt, err)

		testCred := getTestCredential(didKey.String(), time.Now())
		testVCJWT, err := credential.SignVerifiableCredentialJWT(*signer, testCred)
		assert.NoError(tt, err)

		// sleep so the cred expires
		time.Sleep(1 * time.Second)

		presentationClaimJWT := exchange.PresentationClaim{
			Token:                         util.StringPtr(string(testVCJWT)),
			JWTFormat:                     exchange.JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		}

		// build a presentation submission to match
		submissionJWT, err := exchange.BuildPresentationSubmission(*signer, requesterID,
			presentationDefinition, []exchange.PresentationClaim{presentationClaimJWT}, exchange.JWTVPTarget)
		assert.NoError(tt, err)

		result, err := gate.ValidatePresentationSubmission(context.Background(), string(submissionJWT))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential no longer valid")
		assert.False(tt, result.Valid)
	})

	t.Run("Test Custom Expiration Handler - Happy path", func(tt *testing.T) {
		// add new custom handler with a valid input descriptor ID
		inputDescriptorID := presentationDefinition.InputDescriptors[0].ID
		gate, err := NewCredentialGate(CredentialGateConfig{
			AdminDID:               requesterID,
			PresentationDefinition: presentationDefinition,
			CustomHandlers: map[string]CustomHandler{
				inputDescriptorID: newInvalidAfterHandler(inputDescriptorID),
			},
		})
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)

		// signer for the submission
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)

		signer, err := jwx.NewJWXSigner(didKey.String(), expanded.VerificationMethod[0].ID, privKey)
		assert.NoError(tt, err)

		testCred := getTestCredential(didKey.String(), time.Now().Add(time.Hour))
		testVCJWT, err := credential.SignVerifiableCredentialJWT(*signer, testCred)
		assert.NoError(tt, err)
		presentationClaimJWT := exchange.PresentationClaim{
			Token:                         util.StringPtr(string(testVCJWT)),
			JWTFormat:                     exchange.JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		}

		// build a presentation submission to match
		submissionJWT, err := exchange.BuildPresentationSubmission(*signer, requesterID,
			presentationDefinition, []exchange.PresentationClaim{presentationClaimJWT}, exchange.JWTVPTarget)
		assert.NoError(tt, err)

		result, err := gate.ValidatePresentationSubmission(context.Background(), string(submissionJWT))
		assert.NoError(tt, err)
		assert.True(tt, result.Valid)
	})
}

func getTestCredential(did string, invalidAfter time.Time) credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context:      []any{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       did,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":           did,
			"invalidAfter": invalidAfter.Format(time.RFC3339),
		},
	}
}

func newInvalidAfterHandler(inputDescriptorID string) CustomHandler {
	return CustomHandler{
		InputDescriptorID: inputDescriptorID,
		Handler:           invalidAfterHandler,
	}
}

func invalidAfterHandler(_ context.Context, vsd exchange.VerifiedSubmissionData) (bool, error) {
	_, _, cred, err := credential.ToCredential(vsd.Claim)
	if err != nil {
		return false, errors.Wrap(err, "failed to parse credential before checking invalid after")
	}
	exp, err := time.Parse(time.RFC3339, cred.CredentialSubject["invalidAfter"].(string))
	if err != nil {
		return false, errors.Wrap(err, "failed to parse invalid after date")
	}
	if exp.Before(time.Now()) {
		return false, errors.New("credential no longer valid")
	}
	return true, nil
}
