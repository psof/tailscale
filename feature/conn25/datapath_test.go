package conn25

import (
	"fmt"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

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
func TestWoo(t *testing.T) {
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
	p := &packet.Parsed{
		Dst:       netip.AddrPortFrom(mip, 1234),
		Src:       netip.MustParseAddrPort("100.1.2.3:80"),
		IPProto:   ipproto.TCP,
		IPVersion: 4,
	}

	r := dph.HandlePacketsFromTunDevice(p)
	if r != filter.Accept {
		t.Fatal("shoulda bin accept")
	}
	want := netip.AddrPortFrom(tip, 1234)
	if p.Dst != want {
		t.Fatalf("checking p.Dst: want %v, got %v", want, p.Dst)
	}
	fmt.Println(r)
	fmt.Println(p)
}

//test p.dst is a mip but not assoc with a tip => no NAT, return drop
//test p.dst is not a mip, not valid connector return => no NAT, return accept
//test p.dst is not a mip but it is valid connector return traffic => no NAT, return accept

// existing flows use flow table lookup instead of slow path
