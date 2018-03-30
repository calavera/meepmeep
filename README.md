# MeepMeep

MeepMeep is an minimal ACME V2 client library for Go.

It's compatible with the [ACME draft 09](https://tools.ietf.org/html/draft-ietf-acme-acme-09), and it intentionally ignores any draft before that version.

MeepMeep is designed to be used inside an application that handles challenge requests and any other additional logic required to manage ACME certificates.

Documentation: https://godoc.org/github.com/calavera/meepmeep

## State

MeepMeep is still in early development and it has not been tested with Let's Encrypt staging environment yet.

## Development

MeepMeep uses [Pebble](https://github.com/letsencrypt/pebble) as testing ACME server, but you don't need to install it, or run it.
MeepMeep also uses Docker to run tests in isolation.

### Run tests

1. Ensure you have Docker installed and you can [run it as non-root user](https://docs.docker.com/install/linux/linux-postinstall/). See [Docker's installation guide](https://docs.docker.com/install/) if you're not sure about this:

2. Run all tests with `make run-tests`.

## LICENSE

[MIT](LICENSE)
