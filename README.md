# MeepMeep

MeepMeep is an minimal ACME V2 client library for Go.

It's compatible with the [ACME draft 09](https://tools.ietf.org/html/draft-ietf-acme-acme-09), and it intentionally ignores any draft before that version.

MeepMeep is designed to be used inside an application that handles challenge requests and any other additional logic required to manage ACME certificates.

Documentation: https://godoc.org/github.com/calavera/meepmeep

## State

MeepMeep is still in early development and it has not been tested with Let's Encrypt staging environment yet.

## Development

MeepMeep uses [Pebble](https://github.com/letsencrypt/pebble) as testing ACME server. You can run tests with `make test`.

## LICENSE

[MIT](LICENSE)
