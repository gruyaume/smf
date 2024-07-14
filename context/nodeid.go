package context

import (
	"net"

	"github.com/omec-project/pfcp/pfcpType"
)

func NewNodeID(nodeID string) *pfcpType.NodeID {
	ip := net.ParseIP(nodeID)
	if ip == nil {
		return &pfcpType.NodeID{
			NodeIdType:  pfcpType.NodeIdTypeFqdn,
			NodeIdValue: ip,
		}
	} else if ip.To4() != nil {
		return &pfcpType.NodeID{
			NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
			NodeIdValue: ip.To4(),
		}
	} else {
		return &pfcpType.NodeID{
			NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
			NodeIdValue: ip.To16(),
		}
	}
}
