package meepmeep

import (
	"crypto/x509"

	"github.com/letsencrypt/pebble/acme"
)

type authorizationRequest struct {
	Identifier acme.Identifier `json:"identifier"`
}

type challengeRequest struct {
	KeyAuthorization string `json:"keyAuthorization"`
}

type deactivationRequest struct {
	Status string `json:"status"`
}

// Authorization holds information about an ACME authorization.
type Authorization struct {
	acme.Authorization
	URL string
}

// Challenge holds information abount an ACME challenge.
type Challenge struct {
	acme.Challenge
	URL string
}

// Certificate holds a certificate chain in x509 DER format.
type Certificate struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}
