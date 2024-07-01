// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package udp

import (
	"net"

	"github.com/omec-project/smf/logger"
	"github.com/wmnsk/go-pfcp/message"
)

const PFCP_MAX_UDP_LEN = 2048

type PfcpServer struct {
	SrcAddr *net.UDPAddr
}

func NewPfcpServer(srcAddr *net.UDPAddr) *PfcpServer {
	return &PfcpServer{
		SrcAddr: srcAddr,
	}
}

func (pfcpServer *PfcpServer) Listen(Dispatch func(message.Message, *net.UDPAddr)) error {
	conn, err := net.ListenUDP("udp", pfcpServer.SrcAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	logger.PfcpLog.Infof("PFCP server listening on %s", pfcpServer.SrcAddr.String())

	buf := make([]byte, PFCP_MAX_UDP_LEN)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.PfcpLog.Errorf("Error reading from UDP: %v", err)
			continue
		}

		msg, err := message.Parse(buf[:n])
		if err != nil {
			logger.PfcpLog.Errorf("Error parsing PFCP message: %v", err)
			continue
		}

		Dispatch(msg, remoteAddr)
	}
}

func (pfcpServer *PfcpServer) WriteTo(msg message.Message, addr *net.UDPAddr) error {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to dial server: %v", err)
		return err
	}
	defer conn.Close()

	buf := make([]byte, msg.MarshalLen())
	err = msg.MarshalTo(buf)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to marshal PFCP message: %v", err)
		return err
	}

	_, err = conn.Write(buf)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to write to UDP: %v", err)
		return err
	}

	return nil
}
