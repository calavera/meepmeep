package meepmeep

import "github.com/letsencrypt/pebble/acme"

type accountRequest struct {
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed *bool    `json:"termsOfServiceAgreed,omitempty"`
}

// Account holds information about the ACME account.
// The URL field is the key ID to use in privileged order requests.
type Account struct {
	acme.Account
	URL string
}
