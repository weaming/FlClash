package core

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type profileH3Proxy struct {
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (proxy profileH3Proxy) connect(ctx context.Context, dnsResolver resolver.Resolver, host, port string) (net.PacketConn, net.Addr, error) {
	targetPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || targetPort == 0 || proxy.Port < 1 || proxy.Port > 65535 {
		return nil, nil, errors.New("invalid HTTP/3 subscription proxy port")
	}
	client, err := outbound.NewSocks5(outbound.Socks5Option{
		Name:     "subscription",
		Server:   "127.0.0.1",
		Port:     proxy.Port,
		UserName: proxy.Username,
		Password: proxy.Password,
		UDP:      true,
	})
	if err != nil {
		return nil, nil, err
	}
	addresses, err := dnsResolver.LookupIP(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(addresses) == 0 {
		return nil, nil, resolver.ErrIPNotFound
	}
	metadata := &C.Metadata{NetWork: C.UDP, Host: host, DstIP: addresses[0], DstPort: uint16(targetPort)}
	packetConn, err := client.ListenPacketContext(ctx, metadata)
	if err != nil {
		return nil, nil, err
	}
	remote := metadata.UDPAddr()
	return &profileSOCKSPacketConn{
		PacketConn: packetConn,
		target:     N.NewCustomAddr("udp", net.JoinHostPort(host, port), remote),
		remote:     remote,
	}, remote, nil
}

type profileSOCKSPacketConn struct {
	C.PacketConn
	target net.Addr
	remote net.Addr
}

func (conn *profileSOCKSPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	// Sending the hostname allows Mihomo to match domain rules.
	return conn.PacketConn.WriteTo(payload, conn.target)
}

func (conn *profileSOCKSPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	payload, release, _, err := conn.WaitReadFrom()
	if release != nil {
		defer release()
	}
	if err != nil {
		return 0, nil, err
	}
	return copy(buffer, payload), conn.remote, nil
}
