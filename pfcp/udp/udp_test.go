// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func TestRun(t *testing.T) {
	context.SMF_Self().CPNodeID = context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}

	udp.Run(pfcp.Dispatch)

	setupRequest := message.NewAssociationSetupRequest(
		1,
		ie.NewNodeID("127.0.0.1", "", ""),
	)

	dstAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: factory.DEFAULT_PFCP_PORT,
	}

	err := udp.SendPfcp(setupRequest, dstAddr)
	require.Nil(t, err)

	time.Sleep(300 * time.Millisecond)
}
