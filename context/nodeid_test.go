package context_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
)

func TestNewNodeIDIpv4(t *testing.T) {
	nodeID := context.NewNodeID("1.2.3.4")

	if nodeID.NodeIdType != context.NodeIdTypeIpv4Address {
		t.Errorf("Expected NodeIdType to be %d, got %d", context.NodeIdTypeIpv4Address, nodeID.NodeIdType)
	}

	if net.IP(nodeID.NodeIdValue).String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("Expected 1.2.3.4 got %v", net.IP(nodeID.NodeIdValue))
	}
}

func TestNewNodeIDIpv6(t *testing.T) {
	nodeID := context.NewNodeID("2001:db8::68")

	if nodeID.NodeIdType != context.NodeIdTypeIpv6Address {
		t.Errorf("Expected NodeIdType to be %d, got %d", context.NodeIdTypeIpv6Address, nodeID.NodeIdType)
	}

	if net.IP(nodeID.NodeIdValue).String() != net.ParseIP("2001:db8::68").String() {
		t.Errorf("Expected 2001:db8::68 got %v", net.IP(nodeID.NodeIdValue))
	}
}

func TestNewNodeIDFqdn(t *testing.T) {
	nodeID := context.NewNodeID("example.com")

	if nodeID.NodeIdType != context.NodeIdTypeFqdn {
		t.Errorf("Expected NodeIdType to be %d, got %d", context.NodeIdTypeFqdn, nodeID.NodeIdType)
	}

	if net.IP(nodeID.NodeIdValue) != nil {
		t.Errorf("Expected nil got %v", net.IP(nodeID.NodeIdValue))
	}
}
