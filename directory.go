package meepmeep

// Directory holds the ACME directory information
// fetched from a server.
type Directory struct {
	NewNonce    string                 `json:"newNonce"`
	NewAccount  string                 `json:"newAccount"`
	NewOrder    string                 `json:"newOrder"`
	NewAuthz    string                 `json:"newAuthz"`
	RevokeCerts string                 `json:"revokeCerts"`
	KeyExchange string                 `json:"keyExchange"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}
