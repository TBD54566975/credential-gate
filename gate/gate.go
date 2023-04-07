package gate

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
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

	r, err := resolver.NewResolver(localResolverMethods(), config.UniversalResolverURL)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "failed to create resolver")
	}

	return &CredentialGate{
		resolver: r,
		config:   config,
	}, nil
}

func localResolverMethods() []didsdk.Method {
	return []didsdk.Method{didsdk.KeyMethod, didsdk.WebMethod, didsdk.PKHMethod, didsdk.PeerMethod}
}

func (cg *CredentialGate) ValidatePresentation(presentationJWT string) (bool, error) {
	// extract the VP signer's DID, which is set as the iss property as per https://w3c.github.io/vc-jwt/#vp-jwt-1.1
	token, _, err := signing.ParseVerifiablePresentationFromJWT(presentationJWT)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "parsing VP from JWT")
	}
	issuer := token.Issuer()
	kid, ok := token.Get("kid")
	if !ok {
		return false, util.LoggingErrorMsg(err, "getting kid from VP JWT")
	}
	kidStr, ok := kid.(string)
	if !ok {
		return false, util.LoggingErrorMsg(err, "casting kid to string")
	}

	// resolve the VP signer's DID
	did, err := cg.resolver.Resolve(context.Background(), issuer)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "resolving VP signer's DID")
	}
	pubKey, err := GetKeyFromVerificationInformation(did.Document, kidStr)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "getting public key from DID document")
	}

	// construct a verifier after resolving the VP signer's DID
	verifier, err := crypto.NewJWTVerifier(did.ID, kidStr, pubKey)
	if err != nil {
		return false, util.LoggingErrorMsg(err, "constructing JWT verifier")
	}

	// verify the VP JWT's signature
	if _, _, err := signing.VerifyVerifiablePresentationJWT(*verifier, presentationJWT); err != nil {
		return false, util.LoggingErrorMsg(err, "failed to verify VP JWT")
	}

	// validate the VP against the presentation definition
	return true, nil
}
