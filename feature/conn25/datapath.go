package conn25

import (
	"errors"
	"log"
	"net/netip"

	"tailscale.com/envknob"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// datapathHandler is the main implementation of DatapathHandler.
type datapathHandler struct {
	conn25             Connector
	clientFlowTable    *FlowTable
	connectorFlowTable *FlowTable
	logf               logger.Logf
	debugLogging       bool
}

type Connector interface {
	ClientTransitIPForMagicIP(netip.Addr) (netip.Addr, error)
	ConnectorRealIPForTransitIPConnection(netip.Addr, netip.Addr) (netip.Addr, error)
}

func newDatpathHandler(conn25 *Conn25) *datapathHandler {
	return &datapathHandler{
		conn25:             &Conn25{},
		clientFlowTable:    NewFlowTable(0),
		connectorFlowTable: NewFlowTable(0),
		debugLogging:       envknob.Bool("TS_CONN25_DATAPATH_DEBUG"),
	}
}

func (dh *datapathHandler) HandlePacketsFromWireguard(p *packet.Parsed) filter.Response {
	return filter.Accept
	// log.Printf("Handling packet from wireguard: %s", p.String())
	// // Return traffic from connector, source is a Transit IP.
	//
	//	if dh.srcIsTransitIP(p) {
	//		if err := dh.processClientFromConnector(p); err != nil {
	//			// TODO: log error? return error?
	//			// Packets coming in from wireguard with a source
	//			// transit IP that don't have an entry in the flow table should
	//			// be dropped.
	//			return filter.Drop
	//		}
	//		return filter.Accept
	//	}
	//
	// // Outgoing traffic for an external application. Destination is Transit IP.
	//
	//	if dh.selfIsConnector() && dh.dstIPIsTransitIP(p) {
	//		if err := dh.processConnectorFromClient(p); err != nil {
	//			// TODO: log or return error?
	//			// Packets coming in from wireguard with a destination transit IP
	//			// that error should be dropped.
	//			return filter.Drop
	//		}
	//	}
	//
	// return filter.Accept
}

func (dh *datapathHandler) dnatAction(to netip.Addr) PacketAction {
	return PacketAction(func(p *packet.Parsed) { checksum.UpdateDstAddr(p, to) })
}

func (dh *datapathHandler) snatAction(to netip.Addr) PacketAction {
	return PacketAction(func(p *packet.Parsed) { checksum.UpdateSrcAddr(p, to) })
}

func (dh *datapathHandler) debugLogf(msg string, args ...any) {
	if dh.debugLogging {
		dh.logf(msg, args)
	}
}

func (dh *datapathHandler) HandlePacketsFromTunDevice(p *packet.Parsed) filter.Response {
	// Check if this is an existing client flow.
	existing, err := dh.clientFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if err != nil && !errors.Is(err, FlowNotFoundError) {
		dh.debugLogf("error reading client flow table, pass packet umodified: %v", err)
		return filter.Accept
	}

	// Perform the action for the existing client flow and return.
	if err == nil {
		existing.Action(p)
		return filter.Accept
	}

	// Check if this is an existing connector return flow.
	existing, err = dh.connectorFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if err != nil && !errors.Is(err, FlowNotFoundError) {
		dh.debugLogf("error reading connector flow table, pass packet unmodified: %v", err)
		return filter.Accept
	}

	// Perform the action for the existing connector flow and return.
	if err == nil {
		existing.Action(p)
		return filter.Accept
	}

	// The flow was not found in either flow table. Since the packet came in on the
	// tun device, it can only be a new client flow, or other (non-app-connector) traffic.
	magicIP := p.Dst.Addr()
	transitIP, err := dh.conn25.ClientTransitIPForMagicIP(magicIP)
	if err != nil {
		return filter.Accept
	}
	_ = transitIP
	return filter.Accept

	//	entry, err := dh.clientFlowTable.NewFlowFromTunDevice(
	//		FlowData{
	//			Tuple:  flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst),
	//			Action: dh.dnatAction(transitIP),
	//		},
	//		FlowData{
	//			Tuple:  flowtrack.MakeTuple(p.IPProto, netip.AddrPortFrom(transitIP, p.Dst.Port()), p.Src),
	//			Action: dh.snatAction(magicIP),
	//		},
	//	)
	//	if err != nil {
	//		return err
	//	}
	//	entry.Action(p)
	//	log.Printf("Post-processing (new) on client to connector: %s", p.String())
	//	return nil
	//
	// default:
	//
	//		return err
	//	}
	//
	// log.Printf("Handling packet from tun device: %s", p.String())
	// // Connector-bound traffic.
	//
	//	if dh.dstIPIsMagicIP(p) {
	//		if err := dh.processClientToConnector(p); err != nil {
	//			// TODO: log error? return error?
	//			// Packets with a destination Magic IP, that we don't know
	//			// what to do with, should be dropped.
	//			// Perhaps we implement an ICMP error here, while dropping from
	//			// the original datapath.
	//			return filter.Drop
	//		}
	//		return filter.Accept
	//	}
	//
	// // Return traffic from external application.
	//
	//	if dh.selfIsConnector() {
	//		if err := dh.processConnectorToClient(p); err != nil {
	//			switch err {
	//			case nil, FlowNotFoundError:
	//				// If we don't have a record of the flow, it could be normal
	//				// traffic. We don't know if it's interesting connector return
	//				// traffic unless we check the table, since it is not expected
	//				// to have a Transit IP on it yet.
	//				return filter.Accept
	//			default:
	//				return filter.Drop
	//			}
	//		}
	//	}
	//
	// return filter.Accept
}

// processClientToConnector consults the flow table to determine which connector to send the packet to,
// and if this is a new flow, runs the connector selection algorithm, and installs a new flow.
// If the packet is valid, we DNAT from the Magic IP to the Transit IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
//func (dh *datapathHandler) processClientToConnector(p *packet.Parsed) error {
//}

// processClientFromConnector consults the flow table to validate that the packet should
// be forwarded back to the local network stack.
// We SNAT the Transit IP back to the Magic IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processClientFromConnector(p *packet.Parsed) error {
	log.Printf("Proccessing on client from connector: %s", p.String())
	existing, err := dh.clientFlowTable.LookupFromWireguard(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	switch err {
	case nil:
		existing.Action(p)
		log.Printf("Post-processing (existing) on client from connector: %s", p.String())
		return nil
	default:
		return err
	}
}

// processConnectorFromClient consults the flow table to see if this packet is part of
// an existing outbound flow to an application, or a new flow should be installed.
// If the packet is valid, we DNAT from the Transit IP to the external application IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processConnectorFromClient(p *packet.Parsed) error {
	log.Printf("Proccessing on connector from client: %s", p.String())
	existing, err := dh.connectorFlowTable.LookupFromWireguard(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	switch err {
	case nil:
		existing.Action(p)
		log.Printf("Post-processing (new) on connector from client: %s", p.String())
		return nil
	case FlowNotFoundError:
		transitIP := p.Dst.Addr()
		realIP, err := dh.conn25.ConnectorRealIPForTransitIPConnection(p.Src.Addr(), transitIP)
		if err != nil {
			return err
		}
		entry, err := dh.connectorFlowTable.NewFlowFromWireguard(
			FlowData{
				Tuple:  flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst),
				Action: dh.dnatAction(realIP),
			},
			FlowData{
				Tuple:  flowtrack.MakeTuple(p.IPProto, netip.AddrPortFrom(realIP, p.Dst.Port()), p.Src),
				Action: dh.snatAction(transitIP),
			},
		)
		if err != nil {
			return err
		}
		entry.Action(p)
		log.Printf("Post-processing (existing) on connector from client: %s", p.String())
		return nil
	default:
		return err
	}
}

// processConnectorToClient consults the flow table on a connector to determine which client
// to send the return traffic to.
// If the packet is valid, we SNAT the external application IP to the Transit IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processConnectorToClient(p *packet.Parsed) error {
	log.Printf("Proccessing on connector to client: %s", p.String())
	existing, err := dh.connectorFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	switch err {
	case nil:
		existing.Action(p)
		log.Printf("Post-processing (existing) on connector to client: %s", p.String())
		return nil
	default:
		return err
	}
}

//// dstIPIsMagicIP returns whether the destination IP address in p is Magic IP,
//// which could indicate interesting traffic for outbound traffic from a client to a connector.
//func (dh *datapathHandler) dstIPIsMagicIP(p *packet.Parsed) bool {
//	// TODO: implement for real
//	return magicIPs.Contains(p.Dst.Addr())
//}
//
//func (dh *datapathHandler) srcIsTransitIP(p *packet.Parsed) bool {
//	// TODO: implement for real
//	return transitIPs.Contains(p.Src.Addr())
//}
//
//func (dh *datapathHandler) dstIPIsTransitIP(p *packet.Parsed) bool {
//	// TODO: implement for real
//	return transitIPs.Contains(p.Dst.Addr())
//}
//
//// selfIsConnector returns whether this client is running on an app connector.
//func (dh *datapathHandler) selfIsConnector() bool {
//	return dh.conn25.SelfIsConnector()
//}
