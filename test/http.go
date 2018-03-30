package test

import (
	"net"
	"net/http"
	"strings"
)

type HTTPServer struct {
	listener net.Listener
}

// StartHTTP starts a new HTTP server to use in tests.
func StartHTTP(domain, token, authz string) (*HTTPServer, error) {
	l, err := net.Listen("tcp", net.JoinHostPort("", "80"))
	if err != nil {
		return nil, err
	}

	s := &HTTPServer{l}
	s.start(domain, token, authz)

	return s, nil
}

// Stop stops the HTTP server.
func (h *HTTPServer) Stop() {
	h.listener.Close()
}

func (h *HTTPServer) start(domain, token, authz string) {
	path := "/.well-known/acme-challenge/" + token
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("Got validation request at: %s\n", path)
		if strings.HasPrefix(r.Host, domain) && r.Method == "GET" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(authz))
		}
	})

	server := &http.Server{
		Handler: mux,
	}
	server.SetKeepAlivesEnabled(false)
	go server.Serve(h.listener)
}
