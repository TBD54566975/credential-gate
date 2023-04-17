package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/credential-gate/gate"
)

type server struct {
	config    *serverConfig
	gate      *gate.CredentialGate
	responses []gateResponse
}

type getConfig struct {
	AdminDID               string                          `json:"adminDid"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
}

func (s *server) configGetter(w http.ResponseWriter, _ *http.Request) {
	// get serverConfig
	resp := getConfig{
		AdminDID:               s.config.AdminDID.DID,
		PresentationDefinition: s.config.PresentationDefinition,
	}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		logrus.WithError(err).Error("error marshaling serverConfig")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// return serverConfig
	if _, err = w.Write(jsonResp); err != nil {
		logrus.WithError(err).Error("error writing serverConfig")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type gateResponse struct {
	AccessGranted bool   `json:"accessGranted"`
	Message       string `json:"message"`
}

func (s *server) gateHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logrus.WithError(err).Error("error reading request body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var gr gateResponse
	result, err := s.gate.ValidatePresentationSubmission(string(body))
	if err != nil {
		logrus.WithError(err).Error("error validating presentation submission")
		w.WriteHeader(http.StatusBadRequest)
		gr = gateResponse{
			AccessGranted: false,
			Message:       fmt.Sprintf("error validating presentation submission: %s", err.Error()),
		}
	} else {
		var msg string
		if result.Valid {
			msg = "access granted"
		} else {
			msg = "access denied"
			if result.Reason != "" {
				msg = fmt.Sprintf("%s: %s", msg, result.Reason)
			}
		}
		logrus.Info(msg)
		gr = gateResponse{
			AccessGranted: result.Valid,
			Message:       msg,
		}
	}

	// add the new response to the list of responses
	s.responses = append(s.responses, gr)

	jsonResp, err := json.Marshal(gr)
	if err != nil {
		logrus.WithError(err).Error("error marshaling gate response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err = w.Write(jsonResp); err != nil {
		logrus.WithError(err).Error("error writing gate response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *server) responsesHandler(w http.ResponseWriter, _ *http.Request) {
	jsonResp, err := json.Marshal(s.responses)
	if err != nil {
		logrus.WithError(err).Error("error marshaling responses")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err = w.Write(jsonResp); err != nil {
		logrus.WithError(err).Error("error writing responses")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type sampleSubmission struct {
	SubmissionJWT string `json:"submissionJwt"`
}

func (s *server) sampleHandler(w http.ResponseWriter, r *http.Request) {
	// check for the validity flag, if not present assume valid == true
	valid := true
	if r.URL.Query().Get("valid") == "false" {
		valid = false
	}

	var submissionJWT []byte
	var err error
	if valid {
		submissionJWT, err = getSamplePresentationSubmission(s.config.AdminDID.DID, s.config.PresentationDefinition)
	} else {
		submissionJWT, err = getInvalidSamplePresentationSubmission(s.config.AdminDID.DID, s.config.PresentationDefinition)
	}

	if err != nil {
		logrus.WithError(err).Error("error generating sample presentation submission")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// return sample submission
	resp := sampleSubmission{SubmissionJWT: string(submissionJWT)}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		logrus.WithError(err).Error("error marshaling sample presentation submission response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err = w.Write(jsonResp); err != nil {
		logrus.WithError(err).Error("error writing sample presentation submission")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func getSamplePresentationSubmission(adminDID string, definition exchange.PresentationDefinition) ([]byte, error) {
	// generate a new DID key for the submission
	privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
	if err != nil {
		return nil, err
	}

	// signer for the submission and cred
	expanded, err := didKey.Expand()
	if err != nil {
		return nil, err
	}
	signer, err := crypto.NewJWTSigner(didKey.String(), expanded.VerificationMethod[0].ID, privKey)
	if err != nil {
		return nil, err
	}

	// self sign a credential for the submission
	sampleCredential := credential.VerifiableCredential{
		Context:        []any{"https://www.w3.org/2018/credentials/v1"},
		Type:           []string{"VerifiableCredential"},
		Issuer:         didKey.String(),
		IssuanceDate:   time.Now().Format(time.RFC3339),
		ExpirationDate: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":   didKey.String(),
			"name": "Satoshi",
		},
	}

	sampleJWTVC, err := signing.SignVerifiableCredentialJWT(*signer, sampleCredential)
	if err != nil {
		return nil, err
	}

	// create the presentation submission
	presentationClaimJWT := exchange.PresentationClaim{
		TokenBytes:                    sampleJWTVC,
		JWTFormat:                     exchange.JWTVC.Ptr(),
		SignatureAlgorithmOrProofType: string(crypto.EdDSA),
	}
	return exchange.BuildPresentationSubmission(*signer, adminDID,
		definition, []exchange.PresentationClaim{presentationClaimJWT}, exchange.JWTVPTarget)
}

func getInvalidSamplePresentationSubmission(adminDID string, definition exchange.PresentationDefinition) ([]byte, error) {
	// generate a new DID key for the submission
	privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
	if err != nil {
		return nil, err
	}

	// signer for the submission and cred
	expanded, err := didKey.Expand()
	if err != nil {
		return nil, err
	}
	signer, err := crypto.NewJWTSigner(didKey.String(), expanded.VerificationMethod[0].ID, privKey)
	if err != nil {
		return nil, err
	}

	// self sign a credential for the submission
	sampleCredential := credential.VerifiableCredential{
		Context:        []any{"https://www.w3.org/2018/credentials/v1"},
		Type:           []string{"VerifiableCredential"},
		Issuer:         didKey.String(),
		IssuanceDate:   time.Now().Format(time.RFC3339),
		ExpirationDate: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id": didKey.String(),
		},
	}

	sampleJWTVC, err := signing.SignVerifiableCredentialJWT(*signer, sampleCredential)
	if err != nil {
		return nil, err
	}

	submission := exchange.PresentationSubmission{
		ID:           uuid.NewString(),
		DefinitionID: definition.ID,
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:     definition.InputDescriptors[0].ID,
				Format: exchange.JWTVC.String(),
				Path:   "$.verifiableCredential[0]",
			},
		},
	}
	builder := credential.NewVerifiablePresentationBuilder()
	if err = builder.AddContext(exchange.PresentationSubmissionContext); err != nil {
		return nil, err
	}
	if err = builder.AddType(exchange.PresentationSubmissionType); err != nil {
		return nil, err
	}
	if err = builder.SetHolder(didKey.String()); err != nil {
		return nil, err
	}
	if err = builder.AddVerifiableCredentials(string(sampleJWTVC)); err != nil {
		return nil, err
	}
	if err = builder.SetPresentationSubmission(submission); err != nil {
		return nil, err
	}
	vp, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return signing.SignVerifiablePresentationJWT(*signer, signing.JWTVVPParameters{Audience: adminDID}, *vp)
}
