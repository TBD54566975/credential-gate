package main

import (
	"context"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/credential-gate/gate"
)

var (
	pubKeyB58  = "CKVrGgFtpyhpcMNpLZn3Am1DCgnbpTh4EvDbkR49hU2J"
	privKeyB58 = "5aWH9Fd1VyGnzyQSLDCDwgdL5LTFz4P13VbPvXR8HsumB14HesiuA3fDZfVWybmdv94j7aNwnB55WoQtVHQrRbre"
)

// TestGitHubHandlerIntegration tests the GitHub handler - this is an integration test
func TestGitHubHandlerIntegration(t *testing.T) {
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
							Path: []string{"$.vc.type"},
						},
						{
							Path: []string{"$.vc.credentialSubject.gist"},
							Filter: &exchange.Filter{
								Type:    "string",
								Pattern: "^https://gist.githubusercontent.com/.*",
							},
						},
					},
				},
			},
		},
	}

	t.Run("Test GitHub Handler", func(tt *testing.T) {
		// reconstruct pub key and priv key
		pubKeyBytes, err := base58.Decode(pubKeyB58)
		assert.NoError(tt, err)

		privKeyBytes, err := base58.Decode(privKeyB58)
		assert.NoError(tt, err)
		privKey, err := crypto.BytesToPrivKey(privKeyBytes, crypto.Ed25519)
		assert.NoError(tt, err)

		didKey, err := did.CreateDIDKey(crypto.Ed25519, pubKeyBytes)
		assert.NoError(tt, err)
		knownDID, err := didKey.Expand()
		assert.NoError(tt, err)
		knownVerificationMethod := knownDID.VerificationMethod[0].ID

		// add new custom handler with a valid input descriptor ID
		inputDescriptorID := presentationDefinition.InputDescriptors[0].ID
		g, err := gate.NewCredentialGate(gate.CredentialGateConfig{
			AdminDID:               requesterID,
			PresentationDefinition: presentationDefinition,
			CustomHandlers: map[string]gate.CustomHandler{
				inputDescriptorID: NewGitHubHandler(inputDescriptorID),
			},
		})
		assert.NoError(tt, err)

		signer, err := crypto.NewJWTSigner(knownDID.ID, knownVerificationMethod, privKey)
		assert.NoError(tt, err)

		testCred := getTestCredential(knownDID.ID)
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

		result, err := g.ValidatePresentationSubmission(context.Background(), string(submissionJWT))
		assert.NoError(tt, err)
		assert.True(tt, result.Valid)
	})
}

func getTestCredential(knownDID string) credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context:      []any{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential", "GitHubCredential"},
		Issuer:       knownDID,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":   knownDID,
			"gist": "https://gist.githubusercontent.com/decentralgabe/7cd5e914420db14324569bc45a266ad5/raw/6a8ceecf7edd4ac524dec3c5825e0bb7484f77ab/my-did-credgate.txt",
		},
	}
}
