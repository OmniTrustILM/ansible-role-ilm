// Package certheaderencode percent-encodes the header that carries the client
// certificate.
//
// Traefik's passTLSClientCert middleware writes the certificate as plain
// base64, with the PEM markers and newlines removed and nothing escaped. ILM
// core URL-decodes that header before it decodes the base64, because it
// expects the value ingress-nginx produces with $ssl_client_escaped_cert. The
// decoding turns every '+' of the base64 into a space and the certificate is
// rejected with "Illegal base64 character 20". Encoding the value here gives
// core exactly what its decoding step expects.
//
// When the client presents more than its leaf certificate (e.g. leaf plus an
// intermediate), passTLSClientCert joins each certificate's base64 with a
// literal ',' instead of returning just the leaf -- see
// https://github.com/traefik/traefik/issues/13940. The fix for that upstream
// (onlyLeaf) isn't released yet, so we work around it here: core's
// URL-decode-then-base64-decode step has no notion of multiple certificates,
// and $ssl_client_escaped_cert never exposed anything but the leaf either, so
// keeping only the first certificate restores that behavior. Base64 never
// contains a comma, so splitting on the first one is unambiguous.
package certheaderencode

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// DefaultHeader is the header passTLSClientCert writes the certificate to.
const DefaultHeader = "X-Forwarded-Tls-Client-Cert"

// Config holds the plugin configuration.
type Config struct {
	// Header to encode. Defaults to DefaultHeader.
	Header string `json:"header,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{Header: DefaultHeader}
}

type encoder struct {
	next   http.Handler
	name   string
	header string
}

// New creates a new certheaderencode middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	header := config.Header
	if header == "" {
		header = DefaultHeader
	}

	return &encoder{next: next, name: name, header: header}, nil
}

func (e *encoder) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if value := req.Header.Get(e.header); value != "" {
		if leaf, _, found := strings.Cut(value, ","); found {
			value = leaf
		}
		req.Header.Set(e.header, url.QueryEscape(value))
	}

	e.next.ServeHTTP(rw, req)
}
