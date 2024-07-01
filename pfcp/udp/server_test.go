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

func TestServerListen(t *testing.T) {
	// sourceAddress := net.UDPAddr{
	// 	IP:   net.ParseIP("0.0.0.0"),
	// 	Port: 8805,
	// }
	// // s := udp.NewPfcpServer(&sourceAddress)

	// // Reset the flag
	// heartbeatRequestCalled = false

	// // go s.Listen(Dispatch)

	// // Allow some time for the server to start listening
	// // time.Sleep(1 * time.Second)

	// // Send a message to the server
	// conn, err := net.DialUDP("udp", nil, &sourceAddress)
	// if err != nil {
	// 	t.Fatalf("Failed to dial server: %v", err)
	// }
	// defer conn.Close()

	// ts := time.Now()
	// tsIe := ie.NewRecoveryTimeStamp(ts)
	// ipv4Address := net.IPv4(127, 0, 0, 1)
	// ipIe := ie.NewSourceIPAddress(ipv4Address, nil, 0)
	// heartbeatRequest := message.NewHeartbeatResponse(1, tsIe, ipIe)

	// buf, err := heartbeatRequest.Marshal()
	// if err != nil {
	// 	t.Fatalf("Failed to marshal message: %v", err)
	// }

	// _, err = conn.Write(buf)
	// if err != nil {
	// 	t.Fatalf("Failed to send message: %v", err)
	// }

	// // Allow some time for the message to be processed
	// // time.Sleep(1 * time.Second)

	// if !heartbeatRequestCalled {
	// 	t.Errorf("Expected HandlePfcpHeartbeatRequest to be called, but it was not")
	// }

	// if receivedMessage.MessageType() != message.MsgTypeHeartbeatRequest {
	// 	t.Errorf("Expected message type %d, got %d", message.MsgTypeHeartbeatRequest, receivedMessage.MessageType())
	// }

	// if receivedMessage.Sequence() != 1 {
	// 	t.Errorf("Expected sequence number 1, got %d", receivedMessage.Sequence())
	// }
}
