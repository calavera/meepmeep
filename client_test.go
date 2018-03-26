package meepmeep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"testing"

	"github.com/calavera/meepmeep/test"
	"github.com/letsencrypt/pebble/acme"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	defer test.StopPebble()
	test.StartPebble()

	ctx := context.Background()

	dirURL := test.PebbleURL() + "/dir"

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	c, err := NewClient(dirURL, "RS256", pk, NewOptionalHTTPClient(test.PebbleClient()))
	require.NoError(t, err)

	var testAccount *Account

	t.Run("test get directory", func(t *testing.T) {
		d, err := c.GetDirectory(ctx)
		require.NoError(t, err)
		require.Equal(t, test.PebbleURL()+"/sign-me-up", d.NewAccount)
	})

	t.Run("test new account", func(t *testing.T) {
		a, err := c.NewAccount(ctx, "mailto:david.calavera@gmail.com")
		require.NoError(t, err)
		require.Equal(t, "valid", a.Status)

		testAccount = a
	})

	c.WithOptions(NewOptionalAccountKey(testAccount.URL))

	var testOrder *Order

	t.Run("test new order", func(t *testing.T) {
		ids := []acme.Identifier{
			{Type: "dns", Value: "meepmeep.com"},
			{Type: "dns", Value: "*.meepmeep.com"},
		}
		o, err := c.NewOrder(ctx, ids...)
		require.NoError(t, err)
		require.Equal(t, "pending", o.Status)
		require.Len(t, o.Authorizations, 2)

		testOrder = o
	})

	t.Run("test get authorization", func(t *testing.T) {
		for _, u := range testOrder.Authorizations {
			a, err := c.GetAuthorization(ctx, u)
			require.NoError(t, err)
			require.Equal(t, "pending", a.Status)
		}
	})
}

func ExampleNewClient() {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	dirURL := "https://acme-staging-v02.api.letsencrypt.org/directory"
	client, err := NewClient(dirURL, "RS256", pk)
	if err != nil {
		log.Fatal(err)
	}

	client.GetDirectory(context.Background())
}

func ExampleNewClient_withAccountKey() {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	dirURL := "https://acme-staging-v02.api.letsencrypt.org/directory"
	accountKey := "https://acme-staging-v02.api.letsencrypt.org/my-account/96f7fbfaf92c1625a8f4073f3f890b3fc73bc61809753ea60bca687cd417b6f6"

	client, err := NewClient(dirURL, "RS256", pk, NewOptionalAccountKey(accountKey))
	if err != nil {
		log.Fatal(err)
	}

	client.GetDirectory(context.Background())
}

func ExampleNewClient_withHttpClient() {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	dirURL := "https://acme-staging-v02.api.letsencrypt.org/directory"
	accountKey := "https://acme-staging-v02.api.letsencrypt.org/my-account/96f7fbfaf92c1625a8f4073f3f890b3fc73bc61809753ea60bca687cd417b6f6"

	client, err := NewClient(dirURL, "RS256", pk, NewOptionalAccountKey(accountKey), NewOptionalHTTPClient(http.DefaultClient))
	if err != nil {
		log.Fatal(err)
	}

	client.GetDirectory(context.Background())
}
