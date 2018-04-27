package meepmeep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/calavera/meepmeep/test"
	"github.com/letsencrypt/pebble/acme"
	"github.com/stretchr/testify/require"
)

const testHostname = "meepmeep.engineering"

func TestClient(t *testing.T) {
	ps, err := test.StartPebble()
	require.NoError(t, err)
	defer ps.Stop()

	ctx := context.Background()

	dirURL := ps.ServerURL() + "/dir"
	accountURL := ps.ServerURL() + "/sign-me-up"

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	c, err := NewClient(dirURL, "RS256", pk, NewOptionalHTTPClient(ps.Client()))
	require.NoError(t, err)

	var testAccount *Account

	t.Run("test get directory", func(t *testing.T) {
		d, err := c.GetDirectory(ctx)
		require.NoError(t, err)
		require.Equal(t, accountURL, d.NewAccount)
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
			{Type: "dns", Value: testHostname},
		}
		o, err := c.NewOrder(ctx, ids...)
		require.NoError(t, err)
		require.Equal(t, "pending", o.Status)
		require.Len(t, o.Authorizations, 1)

		testOrder = o
	})

	var testChallenge *acme.Challenge

	t.Run("test get authorization", func(t *testing.T) {
		u := testOrder.Authorizations[0]
		a, err := c.GetAuthorization(ctx, u)
		require.NoError(t, err)
		require.Equal(t, "pending", a.Status)

		for _, cc := range a.Challenges {
			if cc.Type == "http-01" {
				testChallenge = cc
				break
			}
		}
	})

	authz, err := c.authorizationKey(testChallenge.Token)
	require.NoError(t, err)

	s, err := test.StartHTTP(testHostname, testChallenge.Token, authz)
	require.NoError(t, err)
	defer s.Stop()

	t.Run("test accept challenge", func(t *testing.T) {
		resp, err := c.AcceptChallenge(ctx, testChallenge)
		require.NoError(t, err)
		require.Equal(t, "pending", resp.Status)

		time.Sleep(500 * time.Millisecond)
		resp, err = c.GetChallenge(ctx, testChallenge.URL)
		require.NoError(t, err)
		require.Equal(t, "valid", resp.Status)
	})

	t.Run("test finalize order", func(t *testing.T) {
		resp, err := c.FinalizeOrder(ctx, testOrder)
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)
		resp, err = c.GetOrder(ctx, testOrder.URL)
		require.NoError(t, err)
		require.Equal(t, "valid", resp.Status)

		testOrder = resp // Update the test order to get the right certificate url
	})

	t.Run("test request certificate", func(t *testing.T) {
		resp, err := c.RequestCertificate(ctx, testOrder.Certificate)
		require.NoError(t, err)
		require.NotNil(t, resp.Certificate)
		require.NotNil(t, resp.Chain)
		require.Len(t, resp.Chain, 1)
	})

	t.Run("test deactivate account", func(t *testing.T) {
		resp, err := c.DeactivateAccount(ctx, testAccount.URL)
		require.NoError(t, err)
		require.Equal(t, "deactivated", resp.Status)
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
