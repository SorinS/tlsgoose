// Go's crypto/tls as the other side, for scripts/go_interop.py:
//
//	gointerop server <cert.pem> <key.pem> <port> [client-cas.pem]
//	    TLS 1.3 server; echoes one line per connection, with whether it resumed and the client
//	    certificate's common name; with client CAs it requires and verifies client certificates
//	gointerop client <port> <roots.pem> <n> [cert.pem key.pem]
//	    n connections sharing a session cache, with a client certificate if given; prints whether
//	    each one resumed, its group and the server's reply
//	gointerop ech-server <cert.pem> <key.pem> <port> <config hex> <private key hex>
//	    TLS 1.3 server with that ECH key (sent as retry); echoes one line per connection, with
//	    whether ECH was accepted and the server name it saw
//	gointerop ech-client <port> <roots.pem> <server name> <ECHConfigList hex> [groups]
//	    one connection offering ECH; prints whether it was accepted and the reply, or the
//	    rejection's retry configs; groups (comma-separated ids, hex) set CurvePreferences
//
// For server and client, $GOINTEROP_TLS12 pins TLS 1.2 ("only") or lets
// it be negotiated ("both"), $GOINTEROP_SUITES (comma-separated ids, hex)
// sets CipherSuites, and the line each connection prints or echoes ends
// with v=<version> suite=<suite>, in hex.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// versions applies $GOINTEROP_TLS12 and $GOINTEROP_SUITES to a config.
func versions(cfg *tls.Config) {
	switch os.Getenv("GOINTEROP_TLS12") {
	case "only":
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	case "both":
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS13
	}
	if s := os.Getenv("GOINTEROP_SUITES"); s != "" {
		for _, x := range strings.Split(s, ",") {
			v, _ := strconv.ParseUint(x, 16, 16)
			cfg.CipherSuites = append(cfg.CipherSuites, uint16(v))
		}
	}
}

// tail is what a line ends with: the version and suite, under $GOINTEROP_TLS12.
func tail(st tls.ConnectionState) string {
	if os.Getenv("GOINTEROP_TLS12") == "" {
		return ""
	}
	return fmt.Sprintf(" v=%04x suite=%04x", st.Version, st.CipherSuite)
}

func main() {
	switch os.Args[1] {
	case "server":
		cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
		if err != nil {
			panic(err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		if len(os.Args) > 5 {
			pem, err := os.ReadFile(os.Args[5])
			if err != nil {
				panic(err)
			}
			cfg.ClientCAs = x509.NewCertPool()
			cfg.ClientCAs.AppendCertsFromPEM(pem)
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		versions(cfg)
		ln, err := tls.Listen("tcp", "127.0.0.1:"+os.Args[4], cfg)
		if err != nil {
			panic(err)
		}
		fmt.Println("ready")
		for {
			c, err := ln.Accept()
			if err != nil {
				panic(err)
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				st := c.(*tls.Conn).ConnectionState()
				client := "-"
				if len(st.PeerCertificates) > 0 {
					client = st.PeerCertificates[0].Subject.CommonName
				}
				fmt.Fprintf(c, "echo %s resumed=%v client=%s%s", line[:len(line)-1], st.DidResume, client, tail(st))
			}(c)
		}
	case "ech-server":
		cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
		if err != nil {
			panic(err)
		}
		config, _ := hex.DecodeString(os.Args[5])
		sk, _ := hex.DecodeString(os.Args[6])
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
			EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: sk, SendAsRetry: true}}}
		ln, err := tls.Listen("tcp", "127.0.0.1:"+os.Args[4], cfg)
		if err != nil {
			panic(err)
		}
		fmt.Println("ready")
		for {
			c, err := ln.Accept()
			if err != nil {
				panic(err)
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					fmt.Println("server error", err)
					return
				}
				st := c.(*tls.Conn).ConnectionState()
				fmt.Fprintf(c, "echo %s ech=%v sni=%s", line[:len(line)-1], st.ECHAccepted, st.ServerName)
			}(c)
		}
	case "ech-client":
		pem, err := os.ReadFile(os.Args[3])
		if err != nil {
			panic(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(pem)
		list, _ := hex.DecodeString(os.Args[5])
		cfg := &tls.Config{RootCAs: roots, ServerName: os.Args[4], MinVersion: tls.VersionTLS13,
			EncryptedClientHelloConfigList: list}
		if len(os.Args) > 6 {
			for _, g := range strings.Split(os.Args[6], ",") {
				v, _ := strconv.ParseUint(g, 16, 16)
				cfg.CurvePreferences = append(cfg.CurvePreferences, tls.CurveID(v))
			}
		}
		c, err := tls.Dial("tcp", "127.0.0.1:"+os.Args[2], cfg)
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) {
			fmt.Printf("rejected retry=%x\n", rej.RetryConfigList)
			return
		}
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Fprintf(c, "hello\n")
		buf := make([]byte, 100)
		k, _ := c.Read(buf)
		st := c.ConnectionState()
		fmt.Printf("ech=%v reply=%q\n", st.ECHAccepted, buf[:k])
		c.Close()
	case "client":
		pem, err := os.ReadFile(os.Args[3])
		if err != nil {
			panic(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(pem)
		cfg := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS13,
			ClientSessionCache: tls.NewLRUClientSessionCache(4)}
		if len(os.Args) > 6 {
			cert, err := tls.LoadX509KeyPair(os.Args[5], os.Args[6])
			if err != nil {
				panic(err)
			}
			cfg.Certificates = []tls.Certificate{cert}
		}
		versions(cfg)
		n, _ := strconv.Atoi(os.Args[4])
		for i := 0; i < n; i++ {
			c, err := tls.Dial("tcp", "127.0.0.1:"+os.Args[2], cfg)
			if err != nil {
				fmt.Println("error", err)
				os.Exit(1)
			}
			fmt.Fprintf(c, "hello %d\n", i)
			buf := make([]byte, 100)
			k, _ := c.Read(buf)
			st := c.ConnectionState()
			fmt.Printf("conn %d resumed=%v group=%v%s reply=%q\n", i, st.DidResume, st.CurveID, tail(st), buf[:k])
			c.Close()
		}
	}
}
