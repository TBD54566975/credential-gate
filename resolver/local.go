package resolver

import (
	"fmt"
	"strings"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/jwk"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/peer"
	"github.com/TBD54566975/ssi-sdk/did/pkh"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/did/web"
	"github.com/pkg/errors"
)

// newLocalResolver builds a multi method DID resolver from a list of methods to support local resolution for
func newLocalResolver(methods []didsdk.Method) (*resolution.MultiMethodResolver, error) {
	if len(methods) == 0 {
		return nil, errors.New("no methods provided")
	}
	resolvers := make([]resolution.Resolver, 0, len(methods))
	for _, method := range methods {
		resolver, err := getKnownResolver(method)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create local resolver for method %s", method)
		}
		resolvers = append(resolvers, resolver)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("no local resolvers created")
	}
	return resolution.NewResolver(resolvers...)
}

// all possible local resolvers
func getKnownResolver(method didsdk.Method) (resolution.Resolver, error) {
	switch method {
	case didsdk.KeyMethod:
		return new(key.Resolver), nil
	case didsdk.WebMethod:
		return new(web.Resolver), nil
	case didsdk.PKHMethod:
		return new(pkh.Resolver), nil
	case didsdk.PeerMethod:
		return new(peer.Resolver), nil
	case didsdk.JWKMethod:
		return new(jwk.Resolver), nil
	}
	return nil, fmt.Errorf("unsupported local resolution method: %s", method)
}

// getMethodForDID gets a DID method from a did, the second part of the did (e.g. did:test:abcd, the method is 'test')
func getMethodForDID(did string) (didsdk.Method, error) {
	split := strings.Split(did, ":")
	if len(split) < 3 {
		return "", errors.New("malformed did: did has fewer than three parts")
	}
	if split[0] != "did" {
		return "", errors.New("malformed did: did must start with `did`")
	}
	return didsdk.Method(split[1]), nil
}
