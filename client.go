package meepmeep

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/letsencrypt/pebble/acme"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	replayNonceKey    = "Replay-Nonce"
	locationKey       = "Location"
	joseContentType   = "application/jose+json"
	deactivatedStatus = "deactivated"
	derFormat         = "application/pkix-cert"
	pemFormat         = "application/pem-certificate-chain; charset=utf-8"
	certificateHeader = "CERTIFICATE"
)

// Client executes requests to the ACME server.
type Client struct {
	accountKey   string
	algorithm    string
	directoryURL string
	signer       crypto.Signer
	directory    *Directory
	hc           *http.Client
}

type nonceSource struct {
	c   *Client
	ctx context.Context
}

func (n nonceSource) Nonce() (string, error) {
	return n.c.nonce(n.ctx)
}

// NewClient creates a new Client with a specific directory.
// The new client requires the algorithm and private key to use to sign requests.
func NewClient(directoryURL, algorithm string, signer crypto.Signer, options ...Optional) (*Client, error) {
	c := &Client{
		algorithm:    algorithm,
		directoryURL: directoryURL,
		signer:       signer,
		hc:           cleanhttp.DefaultClient(),
	}

	return c.WithOptions(options...)
}

// WithOptions allows to change configuration options after a client has been initialize.
// This method is convenient to add the account key to the client if it didn't have it
// when it was initialized.
func (c *Client) WithOptions(options ...Optional) (*Client, error) {
	if len(options) > 0 {
		for _, o := range options {
			if err := o(c); err != nil {
				return nil, errors.Wrap(err, "error configuring meepmeep client")
			}
		}
	}
	return c, nil
}

// GetDirectory fetches the directory payload from the ACME server.
func (c *Client) GetDirectory(ctx context.Context) (*Directory, error) {
	var d Directory

	res, err := c.getRequest(ctx, c.directoryURL)
	if err != nil {
		return nil, errors.Wrap(err, "error requesting directory")
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return nil, errors.Wrap(err, "error decoding directory")
	}

	return &d, nil
}

// NewAccount creates a new ACME account.
// It forces the client to accept the terms of service.
func (c *Client) NewAccount(ctx context.Context, contact ...string) (*Account, error) {
	u, err := c.newAccountURL(ctx)
	if err != nil {
		return nil, err
	}

	agreed := true
	ar := accountRequest{
		Contact:              contact,
		TermsOfServiceAgreed: &agreed,
	}

	res, err := c.postRequest(ctx, u, ar, true)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return nil, reportProblem(res.Body, "error creating new account")
	}

	var a acme.Account
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return nil, errors.Wrap(err, "error decoding new account response")
	}

	return &Account{
		Account: a,
		URL:     res.Header.Get(locationKey),
	}, nil
}

// NewOrder issues a new certificate order with a list of identifiers.
func (c *Client) NewOrder(ctx context.Context, identifiers ...acme.Identifier) (*Order, error) {
	u, err := c.newOrderURL(ctx)
	if err != nil {
		return nil, err
	}

	or := orderRequest{
		Identifiers: identifiers,
	}

	res, err := c.postRequest(ctx, u, or, false)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return decodeOrder(res, http.StatusCreated)
}

// FinalizeOrder changes the order status to finalized.
func (c *Client) FinalizeOrder(ctx context.Context, o *Order) (*Order, error) {
	dnsNames := make([]string, len(o.Identifiers))
	for x, i := range o.Identifiers {
		dnsNames[x] = i.Value
	}

	subj := pkix.Name{
		CommonName: dnsNames[0],
	}

	template := x509.CertificateRequest{
		Subject:  subj,
		DNSNames: dnsNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, c.signer)
	if err != nil {
		return nil, errors.Wrap(err, "error finalizing order")
	}

	fr := finalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrBytes),
	}

	res, err := c.postRequest(ctx, o.Finalize, fr, false)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, reportProblem(res.Body, "error finalizing order")
	}

	var or acme.Order
	if err := json.NewDecoder(res.Body).Decode(&or); err != nil {
		return nil, errors.Wrap(err, "error decoding new order response")
	}

	return &Order{
		Order: or,
		URL:   res.Header.Get(locationKey),
	}, nil
}

// RequestCertificate fetches the final ACME certificate.
func (c *Client) RequestCertificate(ctx context.Context, url string) (*Certificate, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error initializing certificate request")
	}
	req.Header.Set("Accept", derFormat)
	req = req.WithContext(ctx)

	res, err := c.hc.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error requesting certificate")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, reportProblem(res.Body, "error requesting certificate")
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error reading certificate DER data")
	}

	var certs []*x509.Certificate
	if res.Header.Get("Content-Type") == pemFormat {
		ct, err := decodePEMCertificates(b)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificate PEM data")
		}
		certs = ct
	} else {
		ct, err := x509.ParseCertificates(b)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificate DER data")
		}
		certs = ct
	}

	return &Certificate{
		Certificate: certs[0],
		Chain:       certs[1:],
	}, nil
}

// GetAuthorization fetches an ACME authorization.
// This method can be used to check the status after a certificate challenge has been requested.
func (c *Client) GetAuthorization(ctx context.Context, url string) (*Authorization, error) {
	res, err := c.getRequest(ctx, url)
	if err != nil {
		return nil, errors.Wrap(err, "error getting authorization")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, reportProblem(res.Body, "error getting authorization")
	}

	var a acme.Authorization
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return nil, errors.Wrap(err, "error decoding new authorization response")
	}

	return &Authorization{
		Authorization: a,
		URL:           res.Header.Get(locationKey),
	}, nil
}

// DeactivateAuthorization changes the authorization status to deactivated.
// This ensures that a pending authorization can be ignored in a safe way.
func (c *Client) DeactivateAuthorization(ctx context.Context, url string) (*Authorization, error) {
	ar := deactivationRequest{
		Status: deactivatedStatus,
	}

	res, err := c.postRequest(ctx, url, ar, false)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var a acme.Authorization
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return nil, errors.Wrap(err, "error decoding deactivating authorization response")
	}

	return &Authorization{
		Authorization: a,
		URL:           res.Header.Get(locationKey),
	}, nil
}

// AcceptChallenge requests a challenge verification from the ACME server.
func (c *Client) AcceptChallenge(ctx context.Context, challenge *acme.Challenge) (*Challenge, error) {
	key, err := c.authorizationKey(challenge.Token)
	if err != nil {
		return nil, err
	}

	cr := challengeRequest{
		KeyAuthorization: key,
	}

	res, err := c.postRequest(ctx, challenge.URL, cr, false)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return decodeChallenge(res)
}

// GetChallenge requests an existent challenge object from the ACME server.
func (c *Client) GetChallenge(ctx context.Context, url string) (*Challenge, error) {
	res, err := c.getRequest(ctx, url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return decodeChallenge(res)
}

// GetOrder requests an existent order object from the ACME server.
func (c *Client) GetOrder(ctx context.Context, url string) (*Order, error) {
	res, err := c.getRequest(ctx, url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return decodeOrder(res, http.StatusOK)
}

// nonce fetches a new nonce from the ACME server.
// This makes the client to implement JOSE's NonceSource interface:
// https://github.com/square/go-jose/blob/e18a7432cde1d90f722109d29224965a1eec5c79/signing.go#L27
func (c *Client) nonce(ctx context.Context) (string, error) {
	u, err := c.newNonceURL(ctx)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodHead, u, nil)
	req = req.WithContext(ctx)

	res, err := c.hc.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error requesting a new nonce")
	}

	return res.Header.Get(replayNonceKey), nil
}

func (c *Client) getRequest(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error initializing request: %s", url)
	}
	req = req.WithContext(ctx)

	return c.hc.Do(req)
}

func (c *Client) postRequest(ctx context.Context, url string, payload interface{}, jwk bool) (*http.Response, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(payload); err != nil {
		return nil, errors.Wrapf(err, "error encoding request payload: %s", url)
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceSource{c, ctx},
		EmbedJWK:    jwk,
	}
	opts = opts.WithHeader(jose.HeaderKey("url"), url)

	signer, err := jose.NewSigner(c.signingKey(), opts)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating signer for new request: %s", url)
	}

	sign, err := signer.Sign(b.Bytes())
	if err != nil {
		return nil, errors.Wrapf(err, "error signing new request: %s", url)
	}

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(sign.FullSerialize()))
	if err != nil {
		return nil, errors.Wrapf(err, "error initializing request: %s", url)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", joseContentType)

	res, err := c.hc.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "error sending request: %s", url)
	}

	return res, nil
}

func (c *Client) signingKey() jose.SigningKey {
	var k interface{} = c.signer
	if c.accountKey != "" {
		k = jose.JSONWebKey{Algorithm: c.algorithm, KeyID: c.accountKey, Key: c.signer}
	}

	return jose.SigningKey{Algorithm: jose.SignatureAlgorithm(c.algorithm), Key: k}
}

func (c *Client) authorizationKey(token string) (string, error) {
	key := jose.JSONWebKey{Algorithm: c.algorithm, KeyID: c.accountKey, Key: c.signer}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Wrap(err, "error generating the authorization key")
	}

	return token + "." + base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func (c *Client) loadDirectory(ctx context.Context) error {
	d, err := c.GetDirectory(ctx)
	if err != nil {
		return err
	}
	c.directory = d
	return nil
}

func (c *Client) newNonceURL(ctx context.Context) (string, error) {
	if c.directory == nil {
		if err := c.loadDirectory(ctx); err != nil {
			return "", err
		}
	}
	return c.directory.NewNonce, nil
}

func (c *Client) newAccountURL(ctx context.Context) (string, error) {
	if c.directory == nil {
		if err := c.loadDirectory(ctx); err != nil {
			return "", err
		}
	}
	return c.directory.NewAccount, nil
}

func (c *Client) newOrderURL(ctx context.Context) (string, error) {
	if c.directory == nil {
		if err := c.loadDirectory(ctx); err != nil {
			return "", err
		}
	}
	return c.directory.NewOrder, nil
}

func (c *Client) newAuthzURL(ctx context.Context) (string, error) {
	if c.directory == nil {
		if err := c.loadDirectory(ctx); err != nil {
			return "", err
		}
	}
	return c.directory.NewAuthz, nil
}

func reportProblem(body io.ReadCloser, message string) error {
	var d acme.ProblemDetails
	if err := json.NewDecoder(body).Decode(&d); err != nil {
		return errors.Wrap(err, "error decoding problem details :: "+message)
	}
	return errors.Wrap(error(&d), message)
}

func decodeChallenge(res *http.Response) (*Challenge, error) {
	if res.StatusCode != http.StatusOK {
		return nil, reportProblem(res.Body, "error requesting challenge")
	}

	var a acme.Challenge
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return nil, errors.Wrap(err, "error decoding challenge authorization response")
	}

	return &Challenge{
		Challenge: a,
		URL:       res.Header.Get(locationKey),
	}, nil
}

func decodeOrder(res *http.Response, expectedStatus int) (*Order, error) {
	if res.StatusCode != expectedStatus {
		return nil, reportProblem(res.Body, "error processing order")
	}

	var o acme.Order
	if err := json.NewDecoder(res.Body).Decode(&o); err != nil {
		return nil, errors.Wrap(err, "error decoding new order response")
	}

	return &Order{
		Order: o,
		URL:   res.Header.Get(locationKey),
	}, nil
}

func decodePEMCertificates(b []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate

	rest := b
	for rest != nil && len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)

		if block == nil || block.Type != certificateHeader {
			return nil, errors.New("failed to decode PEM block containing certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificate")
		}
		chain = append(chain, cert)
	}

	return chain, nil
}
