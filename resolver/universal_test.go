package resolver

import (
	"context"
	"testing"
	"time"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

// TestUniversalResolver tests the universal resolver's dev instance. It is intentionally skipped to not run in CI.
func TestUniversalResolver(t *testing.T) {
	t.Run("test get methods", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/1.0/methods").
			Persist().
			Reply(200).
			BodyString(`["ion"]`)
		defer gock.Off()

		resolver, err := newUniversalResolver("https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		methods := resolver.Methods()
		assert.NotEmpty(tt, methods)
		assert.Contains(tt, methods, didsdk.Method("ion"))
	})

	t.Run("test get web resolution", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/1.0/methods").
			Reply(200).
			BodyString(`["web"]`)

		gock.New("https://dev.uniresolver.io").
			Get("/1.0/identifiers/did:web:did.actor:alice").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:did.actor:alice"}}`)
		defer gock.Off()

		resolver, err := newUniversalResolver("https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		resolution, err := resolver.Resolve(context.Background(), "did:web:did.actor:alice")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolution)

		assert.Equal(tt, "did:web:did.actor:alice", resolution.Document.ID)
	})

	t.Run("test method cache", func(tt *testing.T) {
		gock.New("https://dev.uniresolver.io").
			Get("/1.0/methods").
			Persist().
			Reply(200).
			BodyString(`["web"]`)

		gock.New("https://dev.uniresolver.io").
			Get("/1.0/identifiers/did:web:did.actor:alice").
			Persist().
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:did.actor:alice"}}`)
		defer gock.Off()

		resolver, err := newUniversalResolver("https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		lastUpdate := resolver.lastCacheUpdate
		assert.Truef(tt, lastUpdate > 0, "last cache update should be set")

		// resolve which won't reset the cache
		resolution, err := resolver.Resolve(context.Background(), "did:web:did.actor:alice")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolution)

		// manually reset cache
		resolver.resetCache()

		resetUpdate := resolver.lastCacheUpdate
		assert.Truef(tt, resetUpdate == 0, "last cache update should be reset")

		time.Sleep(1 * time.Second)

		// get methods repopulates the cache
		methods, err := resolver.GetMethods()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, methods)
		finalUpdate := resolver.lastCacheUpdate
		assert.Greater(tt, finalUpdate, lastUpdate)

		// check if cache is ready for an update
		assert.False(tt, resolver.cacheReadyForUpdate())
	})
}
