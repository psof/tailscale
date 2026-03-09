package conn25

import (
	"fmt"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/wgengine/filter"
)

type testConn25 struct {
	clientTransitIPForMagicIPFn func(magicIP netip.Addr) (netip.Addr, error)
}

func (tc *testConn25) ClientTransitIPForMagicIP(magicIP netip.Addr) (netip.Addr, error) {

}

// test p.dst is a mip and assoc with a tip => should DNAT, return accept
func TestWoo(t *testing.T) {
	mip := netip.MustParseAddrPort("10.64.0.1:24")
	tip := netip.MustParseAddrPort("169.254.0.1:24")
	dph := datapathHandler{}
	p := &packet.Parsed{
		Dst: mip,
	}

	r := dph.HandlePacketsFromTunDevice(p)
	if r != filter.Accept {
		t.Fatal("shoulda bin accept")
	}
	if p.Dst != tip {
		t.Fatal("didn't get the dst we thought")
	}
	fmt.Println(r)
	fmt.Println(p)
}

//test p.dst is a mip but not assoc with a tip => no NAT, return drop
//test p.dst is not a mip, not valid connector return => no NAT, return accept
//test p.dst is not a mip but it is valid connector return traffic => no NAT, return accept

// existing flows use flow table lookup instead of slow path
