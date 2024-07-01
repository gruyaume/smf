// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package udp_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/message"
)

var (
	heartbeatRequestCalled bool
	receivedMessage        message.Message
)

func HandlePfcpHeartbeatRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	heartbeatRequestCalled = true
	receivedMessage = msg
}

func Dispatch(msg message.Message, remoteAddress *net.UDPAddr) {
	messageType := msg.MessageType()
	switch messageType {
	case message.MsgTypeHeartbeatRequest:
		HandlePfcpHeartbeatRequest(msg, remoteAddress)
	default:
		panic("Unknown PFCP message type")
	}
}

func TestNewServer(t *testing.T) {
	sourceAddress := net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 8805,
	}
	s := udp.NewPfcpServer(&sourceAddress)

	if s.SrcAddr != &sourceAddress {
		t.Errorf("Expected %v, got %v", sourceAddress, s.SrcAddr)
	}
}

func TestServerWriteTo(t *testing.T) {
	sourceAddress := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 8805,
	}

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("10.152.183.116"),
		Port: 8805,
	}

	server := udp.NewPfcpServer(sourceAddress)

	msg := message.NewAssociationSetupResponse(1)

	server.WriteTo(msg, remoteAddress)
}
