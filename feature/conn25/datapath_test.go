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

//var mustIP = netip.MustParseAddr
//
//func parsed(proto ipproto.Proto, src, dst string, sport, dport uint16) packet.Parsed {
//	sip, dip := mustIP(src), mustIP(dst)
//
//	var ret packet.Parsed
//	ret.Decode(dummyPacket)
//	ret.IPProto = proto
//	ret.Src = netip.AddrPortFrom(sip, sport)
//	ret.Dst = netip.AddrPortFrom(dip, dport)
//	ret.TCPFlags = packet.TCPSyn
//
//	if sip.Is4() {
//		ret.IPVersion = 4
//	} else {
//		ret.IPVersion = 6
//	}
//
//	return ret
//}

type testConn25 struct {
	clientTransitIPForMagicIPFn             func(netip.Addr) (netip.Addr, error)
	connectorRealIPForTransitIPConnectionFn func(netip.Addr, netip.Addr) (netip.Addr, error)
}

func (tc *testConn25) ClientTransitIPForMagicIP(magicIP netip.Addr) (netip.Addr, error) {
	return tc.clientTransitIPForMagicIPFn(magicIP)
}

func (tc *testConn25) ConnectorRealIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, error) {
	return tc.connectorRealIPForTransitIPConnectionFn(srcIP, transitIP)
}

// test p.dst is a mip and assoc with a tip => should DNAT, return accept
func TestHandlePacketsFromTunDevice(t *testing.T) {
	clientSrcIP := netip.MustParseAddr("100.70.0.1")
	magicIP := netip.MustParseAddr("10.64.0.1")
	unusedMagicIP := netip.MustParseAddr("10.64.0.2")
	transitIP := netip.MustParseAddr("169.254.0.1")
	realIP := netip.MustParseAddr("200.70.0.1")

	clientPort := uint16(1234)
	serverPort := uint16(80)

	tests := []struct {
		description string
		//	transitIPForMagicIPFn  func(netip.Addr) (netip.Addr, error)

		p                      *packet.Parsed
		expectedDst            netip.AddrPort
		expectedFilterResponse filter.Response
	}{
		{
			description: "accept-and-nat-new-client-flow-valid-transit-ip",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(magicIP, serverPort),
			},
			expectedDst:            netip.AddrPortFrom(transitIP, serverPort),
			expectedFilterResponse: filter.Accept,
			assertCached:           true,
		},
		{
			description: "drop-invalid-transit-ip",
			transitIPForMagicIPFn: func(netip.Addr) (netip.Addr, error) {
				return netip.Addr{}, errors.New("no transit IP mapping for magic IP")
			},
			expectedDst:            netip.AddrPortFrom(magicIP, serverPort),
			expectedFilterResponse: filter.Drop,
		},
		// TODO(mzb/fran): some errors should be accepted actually
		//	{
		//		description: "drop-new-client-flow-invalid-transit-ip",
		//		transitIPForMagicIPFn: func(netip.Addr) (netip.Addr, error) {
		//			return netip.Addr{}, errors.New("no transit IP mapping for magic IP")
		//		},
		//		expectedDst:            netip.AddrPortFrom(magicIP, serverPort),
		//		expectedFilterResponse: filter.Drop,
		//	},
		{
			description: "accept-dont-nat-non-app-connector",
			transitIPForMagicIPFn: func(netip.Addr) (netip.Addr, error) {
				return netip.Addr{}, nil
			},
			expectedDst:            netip.AddrPortFrom(magicIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			mock := &testConn25{}

			lookupFnCallCount := 0
			mock.clientTransitIPForMagicIPFn = func(mip netip.Addr) (netip.Addr, error) {
				lookupFnCallCount++
				if mip == magicIP {
					return transitIP, nil
				}
				if mip == unusedMagicIP {
					return netip.Addr{}, errors.New("no transit IP for magic IP")
				}
				return netip.Addr{}, nil
			}
			dph := newDatpathHandler(mock)

			tt.p.IPProto = ipproto.UDP
			tt.p.IPVersion = 4
			tt.p.Decode(dummyPacket)
			p := parsed(ipproto.TCP, "100.1.2.3", magicIP.String(), clientPort, serverPort)
			lookupFnCallCount = 0

			if tt.useFlowCache {

			}

			q := p
			if want, got := tt.expectedFilterResponse, dph.HandlePacketsFromTunDevice(&q); want != got {
				t.Errorf("unexpected filter response: want %v, got %v", want, got)
			}
			if want, got := tt.expectedDst, q.Dst; want != got {
				t.Errorf("unexpected packet dst: want %v, got %v", want, got)
			}

			// Call again and get same result without slow lookup again.
			if tt.assertCached {
				q = p
				if want, got := tt.expectedFilterResponse, dph.HandlePacketsFromTunDevice(&q); want != got {
					t.Errorf("unexpected filter response: want %v, got %v", want, got)
				}
				if want, got := tt.expectedDst, q.Dst; want != got {
					t.Errorf("unexpected packet dst: want %v, got %v", want, got)
				}
				if want, got := 1, lookupFnCallCount; want != got {
					t.Errorf("unexpected call count of ClientTransitIPForMagicIP: want %v, got %v", want, got)
				}
			}
		})
	}
}

//test p.dst is not a mip, not valid connector return traffic => no NAT, return accept
//test p.dst is not a mip but it is valid connector return traffic => no NAT, return accept

// existing flows use flow table lookup instead of slow path - client
// existing flows use flow table lookup instead of slow path - connector
