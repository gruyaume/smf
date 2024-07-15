// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

var (
	heartbeatRequestReceived    bool
	associationResponseReceived bool
)

func HandlePfcpHeartbeatRequestTest(msg *udp.Message) {
	heartbeatRequestReceived = true
}

func HandleAssociationSetupResponseTest(msg *udp.Message) {
	associationResponseReceived = true
}

func Dispatch(msg *udp.Message) {
	msgType := msg.PfcpMessage.MessageType()
	switch msgType {
	case message.MsgTypeHeartbeatRequest:
		HandlePfcpHeartbeatRequestTest(msg)
	case message.MsgTypeAssociationSetupResponse:
		HandleAssociationSetupResponseTest(msg)
	}
}

func SendPfcpMessage(msg message.Message, dstAddr *net.UDPAddr) error {
	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		return err
	}
	_, err = udp.Server.Conn.WriteToUDP(buf, dstAddr)
	if err != nil {
		return err
	}

	return nil
}

func TestRun(t *testing.T) {
	context.SMF_Self().CPNodeID = context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}
	context.SMF_Self().PFCPPort = 8806

	go udp.Run(Dispatch)

	time.Sleep(1 * time.Second)

	setupRequest := message.NewHeartbeatRequest(
		1,
		ie.NewRecoveryTimeStamp(time.Now()),
		nil,
	)

	associationResponse := message.NewAssociationSetupResponse(
		1,
		ie.NewNodeID("2.3.4.5", "", ""),
	)

	dstAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8806,
	}

	err := SendPfcpMessage(setupRequest, dstAddr)
	if err != nil {
		t.Errorf("Failed to send PFCP message: %v", err)
	}

	err = SendPfcpMessage(associationResponse, dstAddr)
	if err != nil {
		t.Errorf("Failed to send PFCP message: %v", err)
	}

	time.Sleep(1 * time.Second)

	if !heartbeatRequestReceived {
		t.Error("Expected Heartbeat Request to be received")
	}

	if !associationResponseReceived {
		t.Error("Expected Association Response to be received")
	}
}

func TestServerSendPfcp(t *testing.T) {
	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8805,
	}

	msg := message.NewAssociationSetupResponse(1)

	err := udp.SendPfcp(msg, remoteAddress, nil)
	if err != nil {
		t.Errorf("Failed to send PFCP message: %v", err)
	}
}

func TestServerNotSetSendPfcp(t *testing.T) {
	udp.Server = nil

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8805,
	}

	msg := message.NewAssociationSetupResponse(1)

	err := udp.SendPfcp(msg, remoteAddress, nil)

	if err == nil {
		t.Error("Expected error, got nil")
	}
}
