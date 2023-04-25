package main

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/credential-gate/gate"
)

func main() {
	// set up gate
	config, err := newCredentialGateServerConfig()
	if err != nil {
		logrus.WithError(err).Fatal("error creating credential gate server")
	}
	credGate, err := gate.NewCredentialGate(gate.CredentialGateConfig{
		AdminDID:               config.AdminDID.DID,
		UniversalResolverURL:   config.UniversalResolverURL,
		PresentationDefinition: config.PresentationDefinition,
	})
	if err != nil {
		logrus.WithError(err).Fatal("error creating credential gate")
	}
	s := server{config: config, gate: credGate}
	logrus.Info("server configured")

	// set up server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello, world!"))
	})

	// get config for the server
	http.HandleFunc("/config", s.configGetter)

	// endpoint to receive credential and run it through the gate
	http.HandleFunc("/gate", s.gateHandler)

	// get a sample credential from the server admin, issued to an ephemeral DID
	// accepts a query parameter ?valid=true and ?valid=false to get a valid or invalid credential
	http.HandleFunc("/sample", s.sampleHandler)

	// endpoint to view all responses
	http.HandleFunc("/responses", s.responsesHandler)

	logrus.Info("server listening...")
	if err = http.ListenAndServe(":8080", nil); err != nil {
		logrus.WithError(err).Fatal("error starting server")
	}
}
