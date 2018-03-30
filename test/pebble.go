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

var (
	logger = log.New(os.Stdout, "Meepmeep ", log.LstdFlags)
)

type PebbleServer struct {
	server *httptest.Server
}

// StartPebble starts a new Pebble server to use in tests.
func StartPebble() (*PebbleServer, error) {
	server := httptest.NewUnstartedServer(nil)
	addr := strings.SplitN(server.Listener.Addr().String(), ":", 2)
	port, err := strconv.Atoi(addr[1])
	if err != nil {
		return nil, err
	}

	os.Setenv("PEBBLE_VA_NOSLEEP", "true")

	clk := clock.Default()
	db := db.NewMemoryStore()
	ca := ca.New(logger, db)
	va := va.New(logger, clk, 80, port)
	wfe := wfe.New(logger, clk, db, va, ca, false)

	server.Config = &http.Server{Handler: wfe.Handler()}

	server.StartTLS()
	return &PebbleServer{server}, nil
}

// Stop stops the Pebble server.
func (s *PebbleServer) Stop() {
	s.server.Close()
}

// ServerURL returns the https url to the test server.
func (s *PebbleServer) ServerURL() string {
	return s.server.URL
}

// Client returns the http client configured to connect
// to the Pebble server with TLS and self-signed, trusted certificates.
func (s *PebbleServer) Client() *http.Client {
	return s.server.Client()
}
