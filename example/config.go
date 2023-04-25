package main

import (
	"crypto"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"

	sdkcrypto "github.com/TBD54566975/ssi-sdk/crypto"

	"github.com/TBD54566975/credential-gate/gate"
)

type serverConfig struct {
	AdminDID               adminDID
	PresentationDefinition exchange.PresentationDefinition
	UniversalResolverURL   string
	CustomHandlers         map[string]gate.CustomHandler
}

type adminDID struct {
	DID      string
	Document did.Document
	KeyID    string
	Key      crypto.PrivateKey
}

// newCredentialGateServerConfig creates a new serverConfig object with a new adminDID
// and a new PresentationDefinition.
func newCredentialGateServerConfig() (*serverConfig, error) {
	definition, err := getPresentationDefinition()
	if err != nil {
		return nil, errors.Wrap(err, "getting gate presentation definition")
	}
	privKey, didKey, err := did.GenerateDIDKey(sdkcrypto.Ed25519)
	if err != nil {
		return nil, errors.Wrap(err, "generating admin did key")
	}
	expanded, err := didKey.Expand()
	if err != nil {
		return nil, errors.Wrap(err, "expanding admin did key")
	}
	return &serverConfig{
		AdminDID: adminDID{
			DID:      didKey.String(),
			Document: *expanded,
			KeyID:    expanded.VerificationMethod[0].ID,
			Key:      privKey,
		},
		PresentationDefinition: *definition,
		UniversalResolverURL:   "https://dev.uniresolver.io",
		CustomHandlers:         map[string]gate.CustomHandler{
			// register custom handlers here
		},
	}, nil
}

// getPresentationDefinition returns a presentation definition that requires a JWT-VP with a JWT-VC that
// has a subject DID of the key method, an issuer DID of the key method, an expiration date, and a name property
func getPresentationDefinition() (*exchange.PresentationDefinition, error) {
	algorithms := sdkcrypto.GetSupportedSignatureAlgs()
	builder := exchange.NewPresentationDefinitionBuilder()
	if err := builder.SetName("Example Credential Gate Presentation Definition"); err != nil {
		return nil, err
	}
	if err := builder.SetPurpose("Provide a credential showing your name"); err != nil {
		return nil, err
	}
	if err := builder.SetClaimFormat(exchange.ClaimFormat{JWTVP: &exchange.JWTType{Alg: algorithms}}); err != nil {
		return nil, err
	}

	// build input descriptor
	idBuilder := exchange.NewInputDescriptorBuilder()
	if err := idBuilder.SetName("Example Credential Gate Input Descriptor"); err != nil {
		return nil, err
	}
	if err := idBuilder.SetClaimFormat(exchange.ClaimFormat{JWTVC: &exchange.JWTType{Alg: algorithms}}); err != nil {
		return nil, err
	}
	if err := idBuilder.SetPurpose("Provide a credential showing your name"); err != nil {
		return nil, err
	}
	constraints := exchange.Constraints{
		Fields: []exchange.Field{
			{
				// require the credential subject to be a DID of the key method
				Path: []string{"$.sub"},
				Filter: &exchange.Filter{
					Type:    "string",
					Pattern: "did:key:*",
				},
			},
			{
				// require the credential to have an issuer DID of the key method
				Path: []string{"$.iss"},
				Filter: &exchange.Filter{
					Type:    "string",
					Pattern: "did:key:*",
				},
			},
			{
				// require the credential to have an expiration date
				Path: []string{"$.exp"},
			},
			{
				// require the credential subject to have a name
				Path: []string{"$.vc.credentialSubject.name"},
				Filter: &exchange.Filter{
					Type:      "string",
					MinLength: 2,
				},
			},
		},
	}
	if err := idBuilder.SetConstraints(constraints); err != nil {
		return nil, err
	}
	inputDescriptor, err := idBuilder.Build()
	if err != nil {
		return nil, err
	}

	if err = builder.SetInputDescriptors([]exchange.InputDescriptor{*inputDescriptor}); err != nil {
		return nil, err
	}
	return builder.Build()
}
