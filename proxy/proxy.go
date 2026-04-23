package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"phantom/fingerprints"
	"phantom/tlsfp"
)

// ConnEvent is emitted for every proxied connection attempt — success, failure, or plain HTTP.
type ConnEvent struct {
	Host    string
	Profile string
	JA3     string
	Time    time.Time
	Err     string
	IsHTTP  bool // plain HTTP request, no TLS fingerprinting involved
}

// Proxy is an HTTP/HTTPS proxy server. CONNECT tunnels get TLS fingerprint spoofing;
// plain HTTP requests are forwarded as-is.
type Proxy struct {
	CA      *CA
	Profile *fingerprints.Profile
	Verbose bool

	// Events receives a ConnEvent for every connection attempt.
	// Sends are non-blocking; nil is fine when no consumer is attached.
	Events chan<- ConnEvent
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleHTTP forwards plain HTTP proxy requests (Firefox sends these for http:// URLs).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	p.emit(ConnEvent{
		Host:   host,
		Time:   time.Now(),
		IsHTTP: true,
	})

	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	hostname := host[:strings.LastIndex(host, ":")]

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	raw, _, err := hj.Hijack()
	if err != nil {
		if p.Verbose {
			log.Printf("hijack %s: %v", hostname, err)
		}
		return
	}
	defer raw.Close()

	fmt.Fprint(raw, "HTTP/1.1 200 Connection Established\r\n\r\n")

	leafCert, err := p.CA.CertForHost(hostname)
	if err != nil {
		log.Printf("[%s] cert: %v", hostname, err)
		p.emit(ConnEvent{Host: hostname, Time: time.Now(), Err: "cert: " + err.Error()})
		return
	}

	clientTLS := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := clientTLS.Handshake(); err != nil {
		// EOF and connection reset mean the browser dropped the connection before
		// completing the handshake — this happens constantly with Firefox's
		// speculative pre-connects. Don't log or emit; it's not an error.
		if isConnDrop(err) {
			return
		}
		log.Printf("[%s] inbound TLS: %v", hostname, err)
		p.emit(ConnEvent{Host: hostname, Time: time.Now(), Err: "cert not trusted — add ~/.phantom/ca.crt to your browser"})
		return
	}
	defer clientTLS.Close()

	targetConn, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		if p.Verbose {
			log.Printf("[%s] dial: %v", hostname, err)
		}
		p.emit(ConnEvent{Host: hostname, Time: time.Now(), Err: "dial: " + err.Error()})
		return
	}
	defer targetConn.Close()

	utlsConn, err := tlsfp.Dial(targetConn, hostname, p.Profile)
	if err != nil {
		log.Printf("[%s] utls setup: %v", hostname, err)
		p.emit(ConnEvent{Host: hostname, Time: time.Now(), Err: "utls: " + err.Error()})
		return
	}
	defer utlsConn.Close()

	if err := utlsConn.Handshake(); err != nil {
		log.Printf("[%s] utls handshake: %v", hostname, err)
		p.emit(ConnEvent{Host: hostname, Time: time.Now(), Err: "handshake: " + err.Error()})
		return
	}

	_, ja3Hash := tlsfp.Compute(p.Profile)
	log.Printf("[%s] profile=%s  ja3=%s", hostname, p.Profile.Name, ja3Hash)

	p.emit(ConnEvent{
		Host:    hostname,
		Profile: p.Profile.Name,
		JA3:     ja3Hash,
		Time:    time.Now(),
	})

	bridge(clientTLS, utlsConn)
}

// isConnDrop returns true for errors that are just the client dropping an idle
// or speculative connection — not worth logging or showing in the dashboard.
func isConnDrop(err error) bool {
	s := err.Error()
	return strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "use of closed")
}

func (p *Proxy) emit(ev ConnEvent) {
	select {
	case p.Events <- ev:
	default:
	}
}

// ListenAndServe starts the proxy on the given address.
func (p *Proxy) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: p,
	}
	log.Printf("phantom listening on %s  profile=%q", addr, p.Profile.Name)
	return srv.ListenAndServe()
}
