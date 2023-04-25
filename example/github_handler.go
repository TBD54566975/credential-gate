package main

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"

	"github.com/TBD54566975/credential-gate/gate"
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

func githubHandler(ctx context.Context, vsd exchange.VerifiedSubmissionData) (bool, error) {
	return false, nil
}
