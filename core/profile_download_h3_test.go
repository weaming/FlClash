package core

import (
	"context"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/miekg/dns"
)

type profileTestResolver struct {
	resolver.Resolver
	port uint16
	ip   netip.Addr
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
	return []netip.Addr{r.ip}, nil
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
	serverAddr := socket.LocalAddr().(*net.UDPAddr)
	dnsResolver := profileTestResolver{port: uint16(serverAddr.Port), ip: netip.MustParseAddr("127.0.0.1")}
	checkDownload := func(t *testing.T, params profileH3Params, dnsResolver profileTestResolver) {
		t.Helper()
		response, err := downloadProfileH3(params, dnsResolver, roots)
		if err != nil {
			t.Fatal(err)
		}
		if response == nil || response.Status != http.StatusOK || string(response.Body) != config ||
			response.Headers.Get("Subscription-Userinfo") != "total=42" {
			t.Fatalf("unexpected subscription response: %+v", response)
		}
	}
	t.Run("direct", func(t *testing.T) {
		checkDownload(t, params, dnsResolver)
	})
	t.Run("authenticated mixed port", func(t *testing.T) {
		tunnel := newProfileTestUDPTunnel(t, serverAddr)
		store := authStore.NewAuthStore(auth.NewAuthenticator([]auth.AuthUser{{User: "profile", Pass: "secret"}}))
		listener, err := mixed.NewWithConfig(LC.AuthServer{
			Enable: true, Listen: "127.0.0.1:0", AuthStore: store,
		}, inbound.NewListenConfig(), tunnel, inbound.WithInName("profile-test"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		udpListener, err := socks.NewUDP(listener.Address(), tunnel, inbound.WithInName("profile-test"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = udpListener.Close() })

		_, port, err := net.SplitHostPort(listener.Address())
		if err != nil {
			t.Fatal(err)
		}
		proxyPort, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		params.Proxy = &profileH3Proxy{Port: proxyPort, Username: "profile", Password: "secret"}
		dnsResolver.ip = netip.MustParseAddr("192.0.2.1")
		checkDownload(t, params, dnsResolver)
		if !tunnel.domainMatched.Load() {
			t.Fatal("the mixed listener did not receive the advertised hostname and port")
		}
		params.Proxy.Password = "wrong-password"
		dnsResolver.ip = netip.MustParseAddr("127.0.0.1")
		if response, err := downloadProfileH3(params, dnsResolver, roots); response != nil || err == nil {
			t.Fatal("a rejected proxy login must fail without trying a direct connection")
		}
	})
}

type profileTestUDPTunnel struct {
	C.Tunnel
	conn          *net.UDPConn
	startRelay    sync.Once
	domainMatched atomic.Bool
}

func newProfileTestUDPTunnel(t *testing.T, target *net.UDPAddr) *profileTestUDPTunnel {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &profileTestUDPTunnel{conn: conn}
}

func (tunnel *profileTestUDPTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	defer packet.Drop()
	if metadata.Host != "edge.example.com" || int(metadata.DstPort) != tunnel.conn.RemoteAddr().(*net.UDPAddr).Port {
		return
	}
	tunnel.domainMatched.Store(true)
	tunnel.startRelay.Do(func() {
		go func() {
			buffer := make([]byte, 64<<10)
			for {
				count, err := tunnel.conn.Read(buffer)
				if err != nil {
					return
				}
				if _, err := packet.WriteBack(buffer[:count], tunnel.conn.RemoteAddr()); err != nil {
					return
				}
			}
		}()
	})
	if _, err := tunnel.conn.Write(packet.Data()); err != nil {
		_ = tunnel.conn.Close()
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
