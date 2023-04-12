package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	urllib "net/url"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
)

// universalResolver is a struct that implements the Resolver interface. It calls the universal resolver endpoint
// to resolve any DID according to https://github.com/decentralized-identity/universal-resolver.
type universalResolver struct {
	client           *http.Client
	url              string
	supportedMethods []didsdk.Method
}

var _ didsdk.Resolver = (*universalResolver)(nil)

func newUniversalResolver(url string) (*universalResolver, error) {
	if url == "" {
		return nil, errors.New("universal resolver url cannot be empty")
	}
	parsedURL, err := urllib.ParseRequestURI(url)
	if err != nil {
		return nil, errors.Wrap(err, "invalid resolver URL")
	}
	if parsedURL.Scheme != "https" {
		return nil, errors.New("invalid resolver URL scheme; must use https")
	}
	ur := universalResolver{
		client: http.DefaultClient,
		url:    url,
	}
	if err = ur.Health(); err != nil {
		return nil, errors.Wrap(err, "checking universal resolver health")
	}
	return &ur, nil
}

func (ur *universalResolver) Health() error {
	if _, err := ur.GetMethods(true); err != nil {
		return errors.New("universal resolver is not healthy")
	}
	return nil
}

// Resolve results resolution results by doing a GET on <url>/1.0.identifiers/<did>.
func (ur *universalResolver) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOption) (*didsdk.ResolutionResult, error) {
	url := ur.url + "/1.0/identifiers/" + did
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}

	resp, err := ur.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing http get")
	}

	respBody, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		return nil, err
	}
	var result didsdk.ResolutionResult
	if err = json.Unmarshal(respBody, &result); err != nil {
		return nil, errors.Wrap(err, "unmarshalling JSON")
	}
	return &result, nil
}

func (ur *universalResolver) Methods() []didsdk.Method {
	methods, _ := ur.GetMethods(false)
	return methods
}

// GetMethods returns the methods that this resolver supports
// as per https://github.com/decentralized-identity/universal-resolver/blob/main/swagger/api.yml#L121
// TODO(gabe) handle cache https://github.com/TBD54566975/credential-gate/issues/8
func (ur *universalResolver) GetMethods(resetCache bool) ([]didsdk.Method, error) {
	// check if we've cached the methods
	if len(ur.supportedMethods) > 0 && !resetCache {
		return ur.supportedMethods, nil
	}

	url := ur.url + "/1.0/methods"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "creating request for universal resolver methods")
	}

	resp, err := ur.client.Do(req)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "performing http get for universal resolver methods")
	}

	respBody, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "reading response body for universal resolver methods")
	}
	var methods []didsdk.Method
	if err = json.Unmarshal(respBody, &methods); err != nil {
		return nil, util.LoggingErrorMsg(err, "unmarshalling response body for universal resolver methods")
	}

	// update the method cache
	ur.supportedMethods = methods
	return methods, nil
}
