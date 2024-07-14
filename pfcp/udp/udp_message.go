// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"net"

	"github.com/wmnsk/go-pfcp/message"
)

type UDPMessage struct {
	RemoteAddr  *net.UDPAddr
	PfcpMessage message.Message
	EventData   interface{}
}

func NewUDPMessage(remoteAddr *net.UDPAddr, pfcpMessage message.Message, eventData interface{}) (msg UDPMessage) {
	msg = UDPMessage{}
	msg.RemoteAddr = remoteAddr
	msg.PfcpMessage = pfcpMessage
	msg.EventData = eventData
	return
}
