// Go's crypto/tls as the other side, for scripts/go_interop.py:
//
//	gointerop server <cert.pem> <key.pem> <port>   TLS 1.3 server; echoes one line per connection
//	gointerop client <port> <roots.pem> <n>         n connections sharing a session cache; prints each one's
//	                                                negotiated group, scheme-less summary and whether it resumed
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
				fmt.Fprintf(c, "echo %s resumed=%v", line[:len(line)-1], st.DidResume)
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
