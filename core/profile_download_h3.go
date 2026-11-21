package core

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/miekg/dns"
)

const maxProfileH3Body = 32 << 20

type profileH3Params struct {
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
}

type profileH3Response struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"`
}

func handleDownloadProfileH3(params profileH3Params) (*profileH3Response, error) {
	return downloadProfileH3(params, resolver.SystemResolver, ca.GetCertPool())
}

func downloadProfileH3(params profileH3Params, dnsResolver resolver.Resolver, roots *x509.CertPool) (*profileH3Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, params.URL, nil)
	if err != nil || request.URL.Scheme != "https" || request.URL.User != nil {
		return nil, errors.New("invalid HTTPS subscription URL")
	}

	host := request.URL.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return nil, nil
	}
	port := request.URL.Port()
	if port == "" {
		port = "443"
	}
	name := dns.Fqdn(host)
	if port != "443" {
		name = "_" + port + "._https." + name
	}
	dnsCtx, cancelDNS := context.WithTimeout(ctx, time.Second)
	target, targetPort := discoverProfileH3(dnsCtx, dnsResolver, name, host, port)
	cancelDNS()
	if target == "" {
		return nil, nil
	}

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, RootCAs: roots},
		Dial: func(ctx context.Context, _ string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			addresses, err := dnsResolver.LookupIP(ctx, target)
			if err != nil {
				return nil, err
			}
			for _, address := range addresses {
				dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				conn, err := quic.DialAddr(dialCtx, net.JoinHostPort(address.String(), targetPort), config, quicConfig)
				cancel()
				if err == nil {
					return conn, nil
				}
			}
			return nil, errors.New("HTTP/3 subscription handshake failed")
		},
	}
	defer transport.Close()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			origin := via[0].URL
			if len(via) >= 5 || next.URL.Scheme != origin.Scheme || !strings.EqualFold(next.URL.Host, origin.Host) {
				return errors.New("HTTP/3 subscription redirected outside its origin or too many times")
			}
			return nil
		},
	}
	for name, values := range params.Headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("HTTP/3 subscription request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProfileH3Body+1))
	if err != nil {
		return nil, errors.New("HTTP/3 subscription response could not be read")
	}
	if len(body) > maxProfileH3Body {
		return nil, errors.New("HTTP/3 subscription response exceeds the size limit")
	}
	return &profileH3Response{Status: response.StatusCode, Headers: response.Header, Body: body}, nil
}

func discoverProfileH3(ctx context.Context, dnsResolver resolver.Resolver, name, host, port string) (string, string) {
	for range 8 {
		query := new(dns.Msg).SetQuestion(name, dns.TypeHTTPS)
		reply, err := dnsResolver.ExchangeContext(ctx, query)
		if err != nil || reply == nil || reply.Rcode != dns.RcodeSuccess {
			break
		}
		alias, target, targetPort := selectProfileH3(reply.Answer, name, host, port)
		if alias == "" {
			return target, targetPort
		}
		name = alias
	}
	return "", ""
}

func selectProfileH3(answers []dns.RR, name, host, port string) (string, string, string) {
	var target, targetPort string
	priority := 1 << 16
	for _, answer := range answers {
		if !strings.EqualFold(answer.Header().Name, name) {
			continue
		}
		if record, ok := answer.(*dns.CNAME); ok {
			return record.Target, "", ""
		}
		record, ok := answer.(*dns.HTTPS)
		if !ok || int(record.Priority) >= priority {
			continue
		}
		if record.Priority == 0 {
			if record.Target == "." {
				return "", "", ""
			}
			return record.Target, "", ""
		}
		candidatePort, hasH3 := profileH3Port(record, port)
		if !hasH3 {
			continue
		}
		target = strings.TrimSuffix(record.Target, ".")
		if record.Target == "." {
			target = host
			if !strings.EqualFold(name, dns.Fqdn(host)) &&
				!strings.EqualFold(name, "_"+port+"._https."+dns.Fqdn(host)) {
				target = strings.TrimSuffix(name, ".")
			}
		}
		targetPort = candidatePort
		priority = int(record.Priority)
	}
	return "", target, targetPort
}

func profileH3Port(record *dns.HTTPS, port string) (string, bool) {
	hasH3 := false
	for _, param := range record.Value {
		switch value := param.(type) {
		case *dns.SVCBAlpn:
			for _, protocol := range value.Alpn {
				hasH3 = hasH3 || protocol == http3.NextProtoH3
			}
		case *dns.SVCBPort:
			if value.Port == 0 {
				return "", false
			}
			port = strconv.Itoa(int(value.Port))
		case *dns.SVCBMandatory:
			for _, key := range value.Code {
				switch key {
				case dns.SVCB_ALPN, dns.SVCB_PORT, dns.SVCB_NO_DEFAULT_ALPN:
				default:
					return "", false
				}
			}
		}
	}
	return port, hasH3
}
