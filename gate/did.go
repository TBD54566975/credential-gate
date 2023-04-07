package gate

import (
	"crypto"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// GetKeyFromVerificationInformation resolves a DID and provides a kid and public key needed for data verification
// it is possible that a DID has multiple verification methods, in which case a kid must be provided, otherwise
// resolution will fail.
// A KID can be fully qualified (e.g. did:example:123#key-1) or just the fragment (e.g. key-1)
// Some DIDs, like did:key, use the entire DID as the KID, so we need to handle all three cases.
func GetKeyFromVerificationInformation(did didsdk.Document, kid string) (crypto.PublicKey, error) {
	if did.IsEmpty() {
		return nil, errors.New("did doc cannot be empty")
	}
	if kid == "" {
		return nil, errors.Errorf("kid is required for did: %s", did.ID)
	}

	verificationMethods := did.VerificationMethod
	if len(verificationMethods) == 0 {
		return nil, errors.Errorf("did<%s> has no verification methods", did.ID)
	}

	for _, method := range verificationMethods {
		methodID := method.ID
		maybeKID1 := kid                               // the kid == the kid
		maybeKID2 := fmt.Sprintf("#%s", kid)           // the kid == the fragment with a #
		maybeKID3 := fmt.Sprintf("%s#%s", did.ID, kid) // the kid == the DID ID + the fragment with a #
		maybeKID4 := fmt.Sprintf("%s%s", did.ID, kid)  // the kid == the DID ID + the fragment without a #
		if methodID == maybeKID1 || methodID == maybeKID2 || methodID == maybeKID3 || methodID == maybeKID4 {
			return extractKeyFromVerificationMethod(method)
		}
	}

	return nil, errors.Errorf("did<%s> has no verification methods with kid: %s", did.ID, kid)
}

func extractKeyFromVerificationMethod(method didsdk.VerificationMethod) (crypto.PublicKey, error) {
	switch {
	case method.PublicKeyMultibase != "":
		pubKeyBytes, multiBaseErr := multibaseToPubKeyBytes(method.PublicKeyMultibase)
		if multiBaseErr != nil {
			return nil, errors.Wrap(multiBaseErr, "converting multibase key")
		}
		return cryptosuite.PubKeyBytesToTypedKey(pubKeyBytes, method.Type)
	case method.PublicKeyBase58 != "":
		pubKeyDecoded, b58Err := base58.Decode(method.PublicKeyBase58)
		if b58Err != nil {
			return nil, errors.Wrap(b58Err, "decoding base58 key")
		}
		return cryptosuite.PubKeyBytesToTypedKey(pubKeyDecoded, method.Type)
	case method.PublicKeyJWK != nil:
		jwkBytes, jwkErr := json.Marshal(method.PublicKeyJWK)
		if jwkErr != nil {
			return nil, errors.Wrap(jwkErr, "marshalling jwk")
		}
		parsed, parseErr := jwk.ParseKey(jwkBytes)
		if parseErr != nil {
			return nil, errors.Wrap(parseErr, "parsing jwk")
		}
		var pubKey crypto.PublicKey
		if err := parsed.Raw(&pubKey); err != nil {
			return nil, errors.Wrap(err, "getting raw jwk")
		}
		return pubKey, nil
	}
	return nil, errors.New("no public key found in verification method")
}

// multibaseToPubKey converts a multibase encoded public key to public key bytes for known multibase encodings
func multibaseToPubKeyBytes(mb string) ([]byte, error) {
	if mb == "" {
		err := fmt.Errorf("could not decode value: %s", mb)
		logrus.WithError(err).Error()
		return nil, err
	}

	encoding, decoded, err := multibase.Decode(mb)
	if err != nil {
		logrus.WithError(err).Error("could not decode multibase key")
		return nil, err
	}
	if encoding != didsdk.Base58BTCMultiBase {
		err = fmt.Errorf("expected %d encoding but found %d", didsdk.Base58BTCMultiBase, encoding)
		logrus.WithError(err).Error()
		return nil, err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	_, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, err
	}
	if n != 2 {
		return nil, errors.New("error parsing multibase varint")
	}
	pubKeyBytes := decoded[n:]
	return pubKeyBytes, nil
}
