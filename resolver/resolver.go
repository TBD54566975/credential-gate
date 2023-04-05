package resolver

import (
	"context"
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Resolver can resolve DIDs using a combination of local and universal resolvers
type Resolver struct {
	lr didsdk.Resolver
	ur *universalResolver
}

// NewResolver creates a new ServiceResolver instance which can resolve DIDs using a combination of local and
// universal resolvers.
func NewResolver(localResolutionMethods []string, universalResolverURL string) (*Resolver, error) {
	if len(localResolutionMethods) == 0 && universalResolverURL == "" {
		return nil, fmt.Errorf("must provide at least one resolution method")
	}

	var lr didsdk.Resolver
	var err error
	if len(localResolutionMethods) > 0 {
		lr, err = newLocalResolver(localResolutionMethods)
		if err != nil {
			return nil, errors.Wrap(err, "instantiating local DID resolver")
		}
	}

	var ur *universalResolver
	if universalResolverURL != "" {
		ur, err = newUniversalResolver(universalResolverURL)
		if err != nil {
			return nil, errors.Wrap(err, "instantiating universal resolver")
		}
	}

	return &Resolver{
		lr: lr,
		ur: ur,
	}, nil
}

// Resolve resolves a DID using a combination of local and universal resolvers. The ordering is as follows:
// 1. Try to resolve with the local resolver
// 2. Try to resolve with the universal resolver
func (r *Resolver) Resolve(ctx context.Context, did string, opts ...didsdk.ResolutionOption) (*didsdk.ResolutionResult, error) {
	method, err := getMethodForDID(did)
	if err != nil {
		return nil, errors.Wrap(err, "getting method for DID")
	}

	// first, try to resolve with the local resolver
	if r.lr != nil && isSupportMethod(method, r.lr.Methods()) {
		locallyResolvedDID, err := r.lr.Resolve(ctx, did, opts...)
		if err == nil {
			return locallyResolvedDID, nil
		}
		logrus.WithError(err).Error("error resolving DID with local resolver")
	}

	// next, resolution with the universal resolver
	if r.ur != nil {
		universallyResolvedDID, err := r.ur.Resolve(ctx, did, opts...)
		if err == nil {
			return universallyResolvedDID, nil

		}
		logrus.WithError(err).Error("error resolving DID with universal resolver")
	}

	return nil, fmt.Errorf("unable to resolve DID %s", did)
}

// isSupportMethod checks if a method is supported by a list of methods
func isSupportMethod(method didsdk.Method, methods []didsdk.Method) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}
