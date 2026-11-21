package core

import (
	"context"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/miekg/dns"
)

type profileTestResolver struct {
	resolver.Resolver
	port uint16
}

func (r profileTestResolver) ExchangeContext(_ context.Context, query *dns.Msg) (*dns.Msg, error) {
	reply := new(dns.Msg).SetReply(query)
	if query.Question[0].Name == "example.com." && query.Question[0].Qtype == dns.TypeHTTPS {
		reply.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET},
			Priority: 1,
			Target:   "edge.example.com.",
			Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3"}}, &dns.SVCBPort{Port: r.port}},
		}}}
	}
	return reply, nil
}

func (r profileTestResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	if host != "edge.example.com" {
		return nil, resolver.ErrIPNotFound
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestDownloadProfileH3(t *testing.T) {
	const config = "proxies: []\n"
	testTLS := httptest.NewTLSServer(nil)
	testTLS.Close()
	cert := testTLS.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(testTLS.Certificate())

	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "example.com" || r.URL.RequestURI() != "/config?version=1" ||
				r.Header.Get("Authorization") != "Basic dGVzdDp0ZXN0" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Subscription-Userinfo", "total=42")
			_, _ = w.Write([]byte(config))
		}),
	}
	go func() { _ = server.Serve(socket) }()
	t.Cleanup(func() { _ = server.Close() })

	params := profileH3Params{
		URL:     "https://example.com/config?version=1",
		Headers: http.Header{"authorization": {"Basic dGVzdDp0ZXN0"}},
	}
	dnsResolver := profileTestResolver{port: uint16(socket.LocalAddr().(*net.UDPAddr).Port)}
	response, err := downloadProfileH3(params, dnsResolver, roots)
	if err != nil {
		t.Fatal(err)
	}
	if response == nil || response.Status != http.StatusOK || string(response.Body) != config ||
		response.Headers.Get("Subscription-Userinfo") != "total=42" {
		t.Fatalf("unexpected subscription response: %+v", response)
	}
}

func TestSelectProfileH3(t *testing.T) {
	const host = "subscription.example"
	for _, test := range []struct {
		name       string
		owner      string
		port       string
		records    []string
		wantAlias  string
		wantTarget string
		wantPort   string
	}{
		{
			name: "HTTP3 only", owner: host + ".", port: "443",
			records:    []string{host + ". 60 IN HTTPS 1 . alpn=h3 no-default-alpn"},
			wantTarget: host, wantPort: "443",
		},
		{
			name: "alternative endpoint", owner: "_8443._https." + host + ".", port: "8443",
			records: []string{
				"_8443._https." + host + ". 60 IN HTTPS 2 . alpn=h3",
				"_8443._https." + host + ". 60 IN HTTPS 1 edge.example. alpn=h2,h3 port=9443",
			},
			wantTarget: "edge.example", wantPort: "9443",
		},
		{
			name: "alias", owner: host + ".", port: "443",
			records:   []string{host + ". 60 IN HTTPS 0 edge.example."},
			wantAlias: "edge.example.",
		},
		{
			name: "no usable HTTP3", owner: host + ".", port: "443",
			records: []string{
				host + ". 60 IN HTTPS 1 . alpn=h2",
				host + ". 60 IN HTTPS 2 . alpn=h3 mandatory=key65400 key65400=value",
				"unrelated.example. 60 IN HTTPS 1 . alpn=h3",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var answers []dns.RR
			for _, record := range test.records {
				answer, err := dns.NewRR(record)
				if err != nil {
					t.Fatal(err)
				}
				answers = append(answers, answer)
			}
			alias, target, port := selectProfileH3(answers, test.owner, host, test.port)
			if alias != test.wantAlias || target != test.wantTarget || port != test.wantPort {
				t.Fatalf("selectProfileH3 returned (%q, %q, %q), want (%q, %q, %q)",
					alias, target, port, test.wantAlias, test.wantTarget, test.wantPort)
			}
		})
	}
}
