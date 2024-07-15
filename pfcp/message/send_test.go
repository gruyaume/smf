// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
)

func BoolPointer(b bool) *bool {
	return &b
}

func TestSendPfcpAssociationSetupRequest(t *testing.T) {
	kafkaInfo := factory.KafkaInfo{
		EnableKafka: BoolPointer(false),
	}
	configuration := &factory.Configuration{
		KafkaInfo:        kafkaInfo,
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}
	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8801,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendPfcpAssociationSetupRequest(upNodeID, 8801)
	if err != nil {
		t.Errorf("Error sending PFCP Association Setup Request: %v", err)
	}
}

func TestSendPfcpAssociationSetupResponse(t *testing.T) {
	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8802,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}

	err = message.SendPfcpAssociationSetupResponse(upNodeID, ie.CauseRequestAccepted, 8802)
	if err != nil {
		t.Errorf("Error sending PFCP Association Setup Response: %v", err)
	}
}

// When the User Plane Node exists in the stored context, then the PFCP Session Establishment Request is sent
func TestSendPfcpSessionEstablishmentRequestUpNodeExists(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	log := logrus.New()
	mockLog := log.WithFields(logrus.Fields{})
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8803,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendPfcpSessionEstablishmentRequest(upNodeID, smContext, pdrList, farList, barList, qerList, 8803)
	if err != nil {
		t.Errorf("Error sending PFCP Session Establishment Request: %v", err)
	}
}

// Given the User Plane Node does not exist in the stored context, then the PFCP Session Establishment Request is not sent
func TestSendPfcpSessionEstablishmentRequestUpNodeDoesNotExist(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	smContext := &context.SMContext{}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8804,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendPfcpSessionEstablishmentRequest(upNodeID, smContext, pdrList, farList, barList, qerList, 8804)
	if err == nil {
		t.Errorf("Expected error sending PFCP Session Establishment Request")
	}
}

func TestSendPfcpSessionModificationRequest(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	log := logrus.New()
	mockLog := log.WithFields(logrus.Fields{})
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8806,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendPfcpSessionModificationRequest(upNodeID, smContext, pdrList, farList, barList, qerList, 8806)
	if err != nil {
		t.Errorf("Error sending PFCP Session Modification Request: %v", err)
	}
}

func TestSendPfcpSessionDeletionRequest(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	log := logrus.New()
	mockLog := log.WithFields(logrus.Fields{})
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8807,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendPfcpSessionDeletionRequest(upNodeID, smContext, 8807)
	if err != nil {
		t.Errorf("Error sending PFCP Session Deletion Request: %v", err)
	}
}

func TestSendPfcpSessionReportResponse(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8808,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8808,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	flags := context.PFCPSRRspFlags{}
	err = message.SendPfcpSessionReportResponse(remoteAddr, ie.CauseRequestAccepted, flags, 1, 1)
	if err != nil {
		t.Errorf("Error sending PFCP Session Report Response: %v", err)
	}
}

func TestSendHeartbeatRequest(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8809,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendHeartbeatRequest(upNodeID, 8809)
	if err != nil {
		t.Errorf("Error sending Heartbeat Request: %v", err)
	}
}

func TestSendHeartbeatResponse(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 7001,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8810,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		Conn: conn,
	}

	err = message.SendHeartbeatResponse(remoteAddr, 1)
	if err != nil {
		t.Errorf("Error sending Heartbeat Response: %v", err)
	}
}
