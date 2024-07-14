// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp_test

// const testPfcpClientPort = 12345

// func TestRun(t *testing.T) {
// 	// Set SMF Node ID

// 	context.SMF_Self().CPNodeID = pfcpType.NodeID{
// 		NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
// 		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
// 	}

// 	udp.Run(pfcp.Dispatch)

// 	testPfcpReq := message.NewAssociationSetupRequest(
// 		1,
// 		ie.NewNodeID("192.168.1.1", "", ""),
// 	)

// 	srcAddr := &net.UDPAddr{
// 		IP:   net.ParseIP("127.0.0.1"),
// 		Port: testPfcpClientPort,
// 	}
// 	dstAddr := &net.UDPAddr{
// 		IP:   net.ParseIP("127.0.0.1"),
// 		Port: udp.PFCP_PORT,
// 	}

// 	err := udp.SendPfcpMessage(testPfcpReq, srcAddr, dstAddr)
// 	require.Nil(t, err)

// 	time.Sleep(300 * time.Millisecond)
// }
