// PROTOTYPE. Throwaway spike server for issue #157. Not the course service.
//
// It exists so the board has something that demands a client certificate. It
// presents the same course service certificate the OTA service presents, so the
// board's compiled-in trust anchor verifies it unchanged, and it requires and
// verifies a client certificate against the manufacturer device authority.
//
// Everything it prints is about the client's half of the handshake, because
// that is the half the spike is testing.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	pkiDir := flag.String("pki", ".course-secrets/pki", "directory holding the course PKI")
	bind := flag.String("bind", "0.0.0.0:8444", "address to listen on")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(*pkiDir, "service.crt.pem"),
		filepath.Join(*pkiDir, "service.key.pem"),
	)
	if err != nil {
		log.Fatalf("service certificate: %v", err)
	}

	deviceCAPEM, err := os.ReadFile(filepath.Join(*pkiDir, "device-ca.crt.pem"))
	if err != nil {
		log.Fatalf("device authority: %v", err)
	}
	deviceCAs := x509.NewCertPool()
	if !deviceCAs.AppendCertsFromPEM(deviceCAPEM) {
		log.Fatal("device authority PEM held no certificate")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    deviceCAs,
		MinVersion:   tls.VersionTLS12,
		// The board's build enables exactly one suite. Pinning the same one
		// here keeps the negotiation from hiding a mismatch.
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		MaxVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				log.Print("client presented no certificate")
				return nil
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				log.Printf("client certificate will not parse: %v", err)
				return err
			}
			log.Printf("client certificate subject %q issuer %q", leaf.Subject, leaf.Issuer)
			log.Printf("client certificate public key %T, chains verified %d",
				leaf.PublicKey, len(chains))
			return nil
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := "unknown"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			name = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		log.Printf("request %s %s from %s, version 0x%04x suite 0x%04x",
			r.Method, r.URL.Path, name, r.TLS.Version, r.TLS.CipherSuite)

		// Issue #158. A 60 byte reply fits in one TLS record and in one
		// recv_buf, so it never asks the poll implementation the hard
		// question. This one does: 64 KiB is several full sized records
		// against a 512 byte recv_buf, so mbedTLS decrypts far more per
		// record than http_client takes per read, and bytes sit buffered
		// in the SSL context with nothing left for the TCP descriptor to
		// signal. That is the case that hangs a naive forwarding poll,
		// and it is the shape of the image download Tier 7 needs.
		if r.URL.Path == "/spike/large" {
			const size = 64 * 1024
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(size))
			payload := bytes.Repeat([]byte("0123456789abcdef"), size/16)
			if _, err := w.Write(payload); err != nil {
				log.Printf("large body write failed: %v", err)
			}
			return
		}

		fmt.Fprintf(w, "mutual TLS reached the handler as %s\n", name)
	})

	listener, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("SPIKE SERVER on %s, requiring a client certificate from the device CA", *bind)

	server := &http.Server{
		Handler:   handler,
		TLSConfig: config,
		ErrorLog:  log.New(os.Stderr, "tls: ", log.LstdFlags),
	}
	log.Fatal(server.ServeTLS(listener, "", ""))
}
