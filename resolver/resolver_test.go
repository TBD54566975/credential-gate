package resolver

import (
	"context"
	"testing"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestResolver(t *testing.T) {
	t.Run("empty resolver", func(tt *testing.T) {
		_, err := NewResolver(nil, "")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "must provide at least one resolution method")
	})

	t.Run("invalid local resolution methods", func(tt *testing.T) {
		_, err := NewResolver([]didsdk.Method{"bad"}, "")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported local resolution method: bad")
	})

	t.Run("valid local resolution method", func(tt *testing.T) {
		resolver, err := NewResolver([]didsdk.Method{"key"}, "")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)
	})

	t.Run("valid local resolution method; resolve supported method", func(tt *testing.T) {
		resolver, err := NewResolver([]didsdk.Method{"key"}, "")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		knownDID := "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
		resolved, err := resolver.Resolve(context.Background(), knownDID)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolved)
		assert.Equal(tt, knownDID, resolved.ID)
	})

	t.Run("valid local resolution method; resolve unsupported method", func(tt *testing.T) {
		resolver, err := NewResolver([]didsdk.Method{"web"}, "")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		knownDID := "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
		_, err = resolver.Resolve(context.Background(), knownDID)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unable to resolve DID")
	})

	t.Run("invalid resolver url", func(tt *testing.T) {
		_, err := NewResolver(nil, "bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid resolver URL")
	})

	t.Run("valid resolver url; not https", func(tt *testing.T) {
		_, err := NewResolver(nil, "http://dev.uniresolver.io")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "must use https")
	})

	t.Run("valid resolver url; health check fails", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/methods").
			Reply(404)
		defer gock.Off()

		_, err := NewResolver(nil, "https://dev.uniresolver.io")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "universal resolver is not healthy")
	})

	t.Run("valid resolver url; health check passes", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/methods").
			Reply(200)
		defer gock.Off()

		resolver, err := NewResolver(nil, "https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)
	})

	t.Run("resolution of local and remote DIDs", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/methods").
			Reply(200)

		gock.New("https://dev.uniresolver.io").
			Get("/1.0/identifiers/did:web:did.actor:alice").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:did.actor:alice"}}`)
		defer gock.Off()

		resolver, err := NewResolver([]didsdk.Method{"key"}, "https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		knownDIDKey := "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
		resolved, err := resolver.Resolve(context.Background(), knownDIDKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolved)
		assert.Equal(tt, knownDIDKey, resolved.ID)

		knownDIDWeb := "did:web:did.actor:alice"
		resolved, err = resolver.Resolve(context.Background(), knownDIDWeb)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolved)
		assert.Equal(tt, knownDIDWeb, resolved.ID)
	})
}
