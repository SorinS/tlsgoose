// Go's crypto/tls as the other side, for scripts/go_interop.py:
//
//	gointerop server <cert.pem> <key.pem> <port> [client-cas.pem]
//	    TLS 1.3 server; echoes one line per connection, with whether it resumed and the client
//	    certificate's common name; with client CAs it requires and verifies client certificates
//	gointerop client <port> <roots.pem> <n> [cert.pem key.pem]
//	    n connections sharing a session cache, with a client certificate if given; prints whether
//	    each one resumed, its group and the server's reply
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
)

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
				fmt.Fprintf(c, "echo %s resumed=%v client=%s", line[:len(line)-1], st.DidResume, client)
			}(c)
		}
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
			fmt.Printf("conn %d resumed=%v group=%v reply=%q\n", i, st.DidResume, st.CurveID, buf[:k])
			c.Close()
		}
	}
}
