package test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
	"github.com/letsencrypt/pebble/wfe"
)

var server *httptest.Server

// StartPebble starts a new Pebble server to use in tests.
func StartPebble() {
	if server != nil {
		return
	}
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)

	server = httptest.NewUnstartedServer(nil)
	addr := strings.SplitN(server.Listener.Addr().String(), ":", 2)
	port, err := strconv.Atoi(addr[1])
	if err != nil {
		logger.Fatal(err)
	}

	clk := clock.Default()
	db := db.NewMemoryStore()
	ca := ca.New(logger, db)
	va := va.New(logger, clk, port, port)
	wfe := wfe.New(logger, clk, db, va, ca, false)

	server.Config = &http.Server{Handler: wfe.Handler()}

	server.StartTLS()
}

// StopPebble stops the Pebble server.
func StopPebble() {
	if server == nil {
		return
	}
	server.Close()
	server = nil
}

// PebbleURL returns the https url to the test server.
func PebbleURL() string {
	return server.URL
}

// PebbleClient returns the http client configured to connect
// to the Pebble server with TLS and self-signed, trusted certificates.
func PebbleClient() *http.Client {
	return server.Client()
}
