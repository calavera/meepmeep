package meepmeep

import (
	"time"

	"github.com/letsencrypt/pebble/acme"
)

type orderRequest struct {
	Identifiers []acme.Identifier `json:"identifiers"`
	NotBefore   *time.Time        `json:"notBefore,omitempty"`
	NotAfter    *time.Time        `json:"notAfter,omitempty"`
}

type finalizeRequest struct {
	CSR string `json:"csr"`
}

// Order hold information about an ACME order.
type Order struct {
	acme.Order
	URL string
}
