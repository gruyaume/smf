// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"net"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/wmnsk/go-pfcp/message"
)

var Server PfcpServer

var ServerStartTime time.Time

func Run(Dispatch func(message.Message, *net.UDPAddr)) {
	sourceAddress := &net.UDPAddr{
		IP:   context.SMF_Self().CPNodeID.ResolveNodeIdToIp(),
		Port: context.SMF_Self().PFCPPort,
	}
	pfcpServer := NewPfcpServer(sourceAddress)
	go pfcpServer.Listen(Dispatch)
	ServerStartTime = time.Now()
}

func SendPfcp(msg message.Message, addr *net.UDPAddr) error {
	err := Server.WriteTo(msg, addr)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to send PFCP message: %v", err)
		metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Failure", err.Error())
		return err
	}
	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Success", "")
	return nil
}
