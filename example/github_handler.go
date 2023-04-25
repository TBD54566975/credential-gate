package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"

	"github.com/TBD54566975/credential-gate/gate"
)

const (
	GitHubCredentialType string = "GitHubCredential"
)

// NewGitHubHandler returns a new GitHub handler
// The GitHub handler checks for a credential of a specific shape, notably, linking
// a GitHub account to a DID. An example GitHub credential is shown below:
//
//	{
//	  "@context": ["https://www.w3.org/2018/credentials/v1"],
//	  "id": "https://example.com/credentials/3732",
//	  "type": ["VerifiableCredential", "GitHubCredential"],
//	  "issuer": "did:example:123",
//	  "issuanceDate": "2020-03-10T04:24:12.164Z",
//	  "credentialSubject": {
//	    "id": "did:example:456",
//	    "gist": "https://gist.github.com/123"
//	  }
//	}
//
// The handler will check that the credential is of type "GitHubCredential" and that
// the credential subject has a "gist" property. The handler will then check that the
// value of the "gist" property is a valid GitHub gist which contains only the string
// "did:example:456", which is the DID of the credential subject.
func NewGitHubHandler(inputDescriptorID string) gate.CustomHandler {
	return gate.CustomHandler{
		InputDescriptorID: inputDescriptorID,
		Handler:           githubHandler,
	}
}

func githubHandler(_ context.Context, vsd exchange.VerifiedSubmissionData) (bool, error) {
	_, _, cred, err := credential.ToCredential(vsd.Claim)
	if err != nil {
		return false, errors.Wrap(err, "failed to parse credential before checking invalid after")
	}
	if !hasGitHubCredentialType(*cred) {
		return false,
			errors.New("credential is not of type GitHubCredential")
	}

	// get file from github and check it against the credential subject
	credSubject, ok := cred.CredentialSubject[credential.VerifiableCredentialIDProperty].(string)
	if !ok {
		return false, errors.New("credential subject does not have ID property")
	}

	// get gist property
	gistURL, ok := vsd.FilteredData.(string)
	if !ok {
		return false, errors.New("credential subject does not have gist property")
	}

	resp, err := http.Get(gistURL)
	if err != nil {
		return false, errors.Wrap(err, "failed to get gist")
	}
	defer resp.Body.Close()
	// read body into a string
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "failed to read gist body")
	}
	if string(body) != credSubject {
		return false, fmt.Errorf("gist<%s> does not contain the credential subject<%s>", string(body), credSubject)
	}
	return true, nil
}

func hasGitHubCredentialType(cred credential.VerifiableCredential) bool {
	types, ok := cred.Type.([]any)
	if !ok {
		return false
	}
	for _, t := range types {
		if t == GitHubCredentialType {
			return true
		}
	}
	return false
}
