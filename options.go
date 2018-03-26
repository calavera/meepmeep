package meepmeep

import (
	"net/http"
)

// Optional is a function interface to
// set optional client settings.
type Optional func(c *Client) error

// NewOptionalHTTPClient allows to use a given http client
// rather than the default http client. Use this if you
// want your http client to handle retries, network partitions,
// and server outages.
func NewOptionalHTTPClient(t *http.Client) Optional {
	return func(c *Client) error {
		c.hc = t
		return nil
	}
}

// NewOptionalAccountKey allows you to set the ACME account key
// for privileged requests. You can get this key from the Account
// object.
func NewOptionalAccountKey(k string) Optional {
	return func(c *Client) error {
		c.accountKey = k
		return nil
	}
}
