package conn25

import (
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// dummyPacket is a 20-byte slice of garbage, to pass the filter
// pre-check when evaluating synthesized packets.
var dummyPacket = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

var mustIP = netip.MustParseAddr

func parsed(proto ipproto.Proto, src, dst string, sport, dport uint16) packet.Parsed {
	sip, dip := mustIP(src), mustIP(dst)

	var ret packet.Parsed
	ret.Decode(dummyPacket)
	ret.IPProto = proto
	ret.Src = netip.AddrPortFrom(sip, sport)
	ret.Dst = netip.AddrPortFrom(dip, dport)
	ret.TCPFlags = packet.TCPSyn

	if sip.Is4() {
		ret.IPVersion = 4
	} else {
		ret.IPVersion = 6
	}

	return ret
}

type testConn25 struct {
	clientTransitIPForMagicIPFn           func(netip.Addr) (netip.Addr, error)
	connectorRealIPForTransitIPConnection func(netip.Addr, netip.Addr) (netip.Addr, error)
}

func (tc *testConn25) ClientTransitIPForMagicIP(magicIP netip.Addr) (netip.Addr, error) {
	return tc.clientTransitIPForMagicIPFn(magicIP)
}

func (tc *testConn25) ConnectorRealIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, error) {
	return tc.connectorRealIPForTransitIPConnection(srcIP, transitIP)
}

// test p.dst is a mip and assoc with a tip => should DNAT, return accept
func TestHandlePacketsFromTunDeviceNewClient(t *testing.T) {
	mip := netip.MustParseAddr("10.64.0.1")
	tip := netip.MustParseAddr("169.254.0.1")
	mock := &testConn25{}
	dph := datapathHandler{
		conn25:             mock,
		clientFlowTable:    NewFlowTable(0),
		connectorFlowTable: NewFlowTable(0),
	}
	mock.clientTransitIPForMagicIPFn = func(netip.Addr) (netip.Addr, error) {
		return tip, nil
	}
	p := parsed(ipproto.TCP, "100.1.2.3", mip.String(), 80, 1234)

	r := dph.HandlePacketsFromTunDevice(&p)
	if r != filter.Accept {
		t.Fatal("shoulda bin accept")
	}
	want := netip.AddrPortFrom(tip, 1234)
	if p.Dst != want {
		t.Fatalf("checking p.Dst: want %v, got %v", want, p.Dst)
	}
}

// test p.dst is a mip but not assoc with a tip => no NAT, return drop
func TestHandlePacketsFromTunDeviceNewClientError(t *testing.T) {
	mip := netip.MustParseAddr("10.64.0.1")

	mock := &testConn25{}
	dph := datapathHandler{
		conn25:             mock,
		clientFlowTable:    NewFlowTable(0),
		connectorFlowTable: NewFlowTable(0),
	}
	mock.clientTransitIPForMagicIPFn = func(netip.Addr) (netip.Addr, error) {
		return netip.Addr{}, errors.New("no mapping for magic IP")
	}
	p := parsed(ipproto.TCP, "100.1.2.3", mip.String(), 80, 1234)

	r := dph.HandlePacketsFromTunDevice(&p)
	if r != filter.Drop {
		t.Fatal("shoulda bin drop")
	}
	want := netip.AddrPortFrom(mip, 1234)
	if p.Dst != want {
		t.Fatalf("checking p.Dst: want %v, got %v", want, p.Dst)
	}
}

//test p.dst is not a mip, not valid connector return traffic => no NAT, return accept
//test p.dst is not a mip but it is valid connector return traffic => no NAT, return accept

// existing flows use flow table lookup instead of slow path
