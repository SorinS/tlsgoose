// Go's crypto/tls as the other side, for scripts/go_interop.py:
//
//	gointerop server -cert cert.pem -key key.pem -port n [-client-cas cas.pem] [-tls12 only|both] [-suites ids]
//	    TLS 1.3 server; echoes one line per connection, with whether it resumed and the client
//	    certificate's common name; with client CAs it requires and verifies client certificates
//	gointerop client -port n -roots roots.pem -n count [-cert cert.pem -key key.pem] [-tls12 only|both] [-suites ids]
//	    count connections sharing a session cache, with a client certificate if given; prints
//	    whether each one resumed, its group and the server's reply
//	gointerop ech-server -cert cert.pem -key key.pem -port n -ech-config hex -ech-key hex
//	    TLS 1.3 server with that ECH key (sent as retry); echoes one line per connection, with
//	    whether ECH was accepted and the server name it saw
//	gointerop ech-client -port n -roots roots.pem -server-name name -ech-configs hex [-groups ids]
//	    one connection offering ECH; prints whether it was accepted and the reply, or the
//	    rejection's retry configs
//	gointerop -version
//
// -tls12 pins TLS 1.2 ("only") or lets it be negotiated ("both"), and the
// line each connection prints or echoes then ends with v=<version>
// suite=<suite>, in hex. -suites sets CipherSuites, -groups
// CurvePreferences: comma-separated ids, in hex.
//
// Errors go to stderr: a bad command line exits 2, anything else 1.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

const version = "1.0.0"

const usage = `usage: gointerop server -cert cert.pem -key key.pem -port n [-client-cas cas.pem] [-tls12 only|both] [-suites ids]
       gointerop client -port n -roots roots.pem -n count [-cert cert.pem -key key.pem] [-tls12 only|both] [-suites ids]
       gointerop ech-server -cert cert.pem -key key.pem -port n -ech-config hex -ech-key hex
       gointerop ech-client -port n -roots roots.pem -server-name name -ech-configs hex [-groups ids]
       gointerop -version
`

// hexBytes is a flag given in hex.
type hexBytes []byte

func (b *hexBytes) String() string { return hex.EncodeToString(*b) }

func (b *hexBytes) Set(s string) (err error) {
	*b, err = hex.DecodeString(s)
	return err
}

// hexIDs is a flag of comma-separated 16-bit ids in hex: cipher suites, groups.
type hexIDs[T ~uint16] []T

func (l *hexIDs[T]) String() string {
	var s []string
	for _, v := range *l {
		s = append(s, fmt.Sprintf("%04x", uint16(v)))
	}
	return strings.Join(s, ",")
}

func (l *hexIDs[T]) Set(s string) error {
	for _, x := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(x, 16, 16)
		if err != nil {
			return fmt.Errorf("%q is not a 16-bit id in hex", x)
		}
		*l = append(*l, T(v))
	}
	return nil
}

// tls12Mode is -tls12: "", "only" or "both".
type tls12Mode string

func (m *tls12Mode) String() string { return string(*m) }

func (m *tls12Mode) Set(s string) error {
	if s != "only" && s != "both" {
		return errors.New(`must be "only" or "both"`)
	}
	*m = tls12Mode(s)
	return nil
}

// apply sets the versions -tls12 allows.
func (m tls12Mode) apply(cfg *tls.Config) {
	switch m {
	case "only":
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	case "both":
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS13
	}
}

// tail is what a line ends with: the version and suite, under -tls12.
func (m tls12Mode) tail(st tls.ConnectionState) string {
	if m == "" {
		return ""
	}
	return fmt.Sprintf(" v=%04x suite=%04x", st.Version, st.CipherSuite)
}

// fail reports a bad command line and exits 2.
func fail(fs *flag.FlagSet, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gointerop %s: %s\n", fs.Name(), fmt.Sprintf(format, args...))
	fs.Usage()
	os.Exit(2)
}

// parse reads a mode's flags and checks that the required ones are there.
func parse(fs *flag.FlagSet, args []string, required ...string) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage of gointerop %s:\n", fs.Name())
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() > 0 {
		fail(fs, "unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, name := range required {
		if !set[name] {
			fail(fs, "-%s is required", name)
		}
	}
}

// roots reads a PEM file of CA certificates.
func roots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return pool, nil
}

// listen accepts connections on 127.0.0.1:port, after printing "ready", and
// answers each one's first line with reply's.
func listen(port int, cfg *tls.Config, reply func(line string, st tls.ConnectionState) string) error {
	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		return err
	}
	fmt.Println("ready")
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "gointerop: %s: %v\n", c.RemoteAddr(), err)
				return
			}
			fmt.Fprint(c, reply(strings.TrimSuffix(line, "\n"), c.(*tls.Conn).ConnectionState()))
		}(c)
	}
}

// exchange sends line on c and returns the reply. The peer's close_notify
// can come with it, as io.EOF beside the data.
func exchange(c *tls.Conn, line string) (string, error) {
	if _, err := fmt.Fprint(c, line); err != nil {
		return "", err
	}
	buf := make([]byte, 100)
	k, err := c.Read(buf)
	if err != nil && !(errors.Is(err, io.EOF) && k > 0) {
		return "", err
	}
	return string(buf[:k]), nil
}

func server(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var certFile, keyFile, clientCAs string
	var port int
	var tls12 tls12Mode
	var suites hexIDs[uint16]
	fs.StringVar(&certFile, "cert", "", "the server's certificate chain (PEM)")
	fs.StringVar(&keyFile, "key", "", "its private key (PEM)")
	fs.IntVar(&port, "port", 0, "the port to listen on, on 127.0.0.1")
	fs.StringVar(&clientCAs, "client-cas", "", "require client certificates from these CAs (PEM)")
	fs.Var(&tls12, "tls12", "`mode`: TLS 1.2 only, or both 1.2 and 1.3 (only|both)")
	fs.Var(&suites, "suites", "cipher suites, comma-separated `ids` in hex")
	parse(fs, args, "cert", "key", "port")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CipherSuites: suites}
	if clientCAs != "" {
		if cfg.ClientCAs, err = roots(clientCAs); err != nil {
			return err
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	tls12.apply(cfg)
	return listen(port, cfg, func(line string, st tls.ConnectionState) string {
		client := "-"
		if len(st.PeerCertificates) > 0 {
			client = st.PeerCertificates[0].Subject.CommonName
		}
		return fmt.Sprintf("echo %s resumed=%v client=%s%s", line, st.DidResume, client, tls12.tail(st))
	})
}

func client(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var rootsFile, certFile, keyFile string
	var port, n int
	var tls12 tls12Mode
	var suites hexIDs[uint16]
	fs.IntVar(&port, "port", 0, "the server's port, on 127.0.0.1")
	fs.StringVar(&rootsFile, "roots", "", "the CAs to trust (PEM)")
	fs.IntVar(&n, "n", 1, "how many connections, sharing a session cache")
	fs.StringVar(&certFile, "cert", "", "a client certificate chain (PEM)")
	fs.StringVar(&keyFile, "key", "", "its private key (PEM)")
	fs.Var(&tls12, "tls12", "`mode`: TLS 1.2 only, or both 1.2 and 1.3 (only|both)")
	fs.Var(&suites, "suites", "cipher suites, comma-separated `ids` in hex")
	parse(fs, args, "port", "roots")
	if (certFile == "") != (keyFile == "") {
		fail(fs, "-cert and -key go together")
	}

	pool, err := roots(rootsFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS13,
		CipherSuites: suites, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	tls12.apply(cfg)
	for i := 0; i < n; i++ {
		c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
		if err != nil {
			return fmt.Errorf("connection %d: %w", i, err)
		}
		reply, err := exchange(c, fmt.Sprintf("hello %d\n", i))
		st := c.ConnectionState()
		c.Close()
		if err != nil {
			return fmt.Errorf("connection %d: %w", i, err)
		}
		fmt.Printf("conn %d resumed=%v group=%v%s reply=%q\n", i, st.DidResume, st.CurveID, tls12.tail(st), reply)
	}
	return nil
}

func echServer(args []string) error {
	fs := flag.NewFlagSet("ech-server", flag.ExitOnError)
	var certFile, keyFile string
	var port int
	var config, key hexBytes
	fs.StringVar(&certFile, "cert", "", "the server's certificate chain (PEM)")
	fs.StringVar(&keyFile, "key", "", "its private key (PEM)")
	fs.IntVar(&port, "port", 0, "the port to listen on, on 127.0.0.1")
	fs.Var(&config, "ech-config", "the ECHConfig, in `hex`")
	fs.Var(&key, "ech-key", "its private key, in `hex`")
	parse(fs, args, "cert", "key", "port", "ech-config", "ech-key")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key, SendAsRetry: true}}}
	return listen(port, cfg, func(line string, st tls.ConnectionState) string {
		return fmt.Sprintf("echo %s ech=%v sni=%s", line, st.ECHAccepted, st.ServerName)
	})
}

func echClient(args []string) error {
	fs := flag.NewFlagSet("ech-client", flag.ExitOnError)
	var rootsFile, serverName string
	var port int
	var configs hexBytes
	var groups hexIDs[tls.CurveID]
	fs.IntVar(&port, "port", 0, "the server's port, on 127.0.0.1")
	fs.StringVar(&rootsFile, "roots", "", "the CAs to trust (PEM)")
	fs.StringVar(&serverName, "server-name", "", "the server name to send encrypted")
	fs.Var(&configs, "ech-configs", "the ECHConfigList, in `hex`")
	fs.Var(&groups, "groups", "key exchange groups, comma-separated `ids` in hex")
	parse(fs, args, "port", "roots", "server-name", "ech-configs")

	pool, err := roots(rootsFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13,
		EncryptedClientHelloConfigList: configs, CurvePreferences: groups}
	c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if rej := (*tls.ECHRejectionError)(nil); errors.As(err, &rej) {
		fmt.Printf("rejected retry=%x\n", rej.RetryConfigList)
		return nil
	}
	if err != nil {
		return err
	}
	defer c.Close()
	reply, err := exchange(c, "hello\n")
	if err != nil {
		return err
	}
	fmt.Printf("ech=%v reply=%q\n", c.ConnectionState().ECHAccepted, reply)
	return nil
}

// printVersion prints this program's version, the Go it was built with and,
// when go build stamped it, the commit it was built from.
func printVersion() {
	rev := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		var dirty bool
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if rev != "" && dirty {
			rev += "+dirty"
		}
	}
	line := fmt.Sprintf("gointerop %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if rev != "" {
		line += " " + rev
	}
	fmt.Println(line)
}

func main() {
	modes := map[string]func([]string) error{
		"server": server, "client": client, "ech-server": echServer, "ech-client": echClient,
	}
	if len(os.Args) == 2 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		printVersion()
		return
	}
	if len(os.Args) < 2 || modes[os.Args[1]] == nil {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := modes[os.Args[1]](os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "gointerop %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}
