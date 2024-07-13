// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"

	"github.com/omec-project/pfcp/pfcpType"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp/message"
)

type PFCPState struct {
	nodeID  pfcpType.NodeID
	pdrList []*context.PDR
	farList []*context.FAR
	qerList []*context.QER
	port    uint16
}

// SendPFCPRule send one datapath to UPF
func SendPFCPRule(smContext *context.SMContext, dataPath *context.DataPath) {
	logger.PduSessLog.Infoln("Send PFCP Rule")
	logger.PduSessLog.Infoln("DataPath: ", dataPath)
	for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		pdrList := make([]*context.PDR, 0, 2)
		farList := make([]*context.FAR, 0, 2)
		qerList := make([]*context.QER, 0, 2)

		if curDataPathNode.UpLinkTunnel != nil && curDataPathNode.UpLinkTunnel.PDR != nil {
			for _, pdr := range curDataPathNode.UpLinkTunnel.PDR {
				pdrList = append(pdrList, pdr)
				farList = append(farList, pdr.FAR)
				if pdr.QER != nil {
					qerList = append(qerList, pdr.QER...)
				}
			}
		}
		if curDataPathNode.DownLinkTunnel != nil && curDataPathNode.DownLinkTunnel.PDR != nil {
			for _, pdr := range curDataPathNode.DownLinkTunnel.PDR {
				pdrList = append(pdrList, pdr)
				farList = append(farList, pdr.FAR)
				if pdr.QER != nil {
					qerList = append(qerList, pdr.QER...)
				}
			}
		}

		sessionContext, exist := smContext.PFCPContext[curDataPathNode.GetNodeIP()]
		remoteAddress := &net.UDPAddr{
			IP:   curDataPathNode.UPF.NodeID.ResolveNodeIdToIp(),
			Port: int(curDataPathNode.UPF.Port),
		}
		if !exist || sessionContext.RemoteSEID == 0 {
			message.SendPfcpSessionEstablishmentRequest(
				remoteAddress, curDataPathNode.UPF.NodeID, smContext, pdrList, farList, qerList)
		} else {
			message.SendPfcpSessionModificationRequest(
				remoteAddress, curDataPathNode.UPF.NodeID, smContext, pdrList, farList, qerList)
		}
	}
}

// SendPFCPRules send all datapaths to UPFs
func SendPFCPRules(smContext *context.SMContext) {
	pfcpPool := make(map[string]*PFCPState)

	for _, dataPath := range smContext.Tunnel.DataPathPool {
		if dataPath.Activated {
			for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
				pdrList := make([]*context.PDR, 0, 2)
				farList := make([]*context.FAR, 0, 2)
				qerList := make([]*context.QER, 0, 2)

				if curDataPathNode.UpLinkTunnel != nil && curDataPathNode.UpLinkTunnel.PDR != nil {
					for _, pdr := range curDataPathNode.UpLinkTunnel.PDR {
						pdrList = append(pdrList, pdr)
						farList = append(farList, pdr.FAR)
						if pdr.QER != nil {
							qerList = append(qerList, pdr.QER...)
						}
					}
				}
				if curDataPathNode.DownLinkTunnel != nil && curDataPathNode.DownLinkTunnel.PDR != nil {
					for _, pdr := range curDataPathNode.DownLinkTunnel.PDR {
						pdrList = append(pdrList, pdr)
						farList = append(farList, pdr.FAR)

						if pdr.QER != nil {
							qerList = append(qerList, pdr.QER...)
						}
					}
				}

				pfcpState := pfcpPool[curDataPathNode.GetNodeIP()]
				if pfcpState == nil {
					pfcpPool[curDataPathNode.GetNodeIP()] = &PFCPState{
						nodeID:  curDataPathNode.UPF.NodeID,
						port:    curDataPathNode.UPF.Port,
						pdrList: pdrList,
						farList: farList,
						qerList: qerList,
					}
				} else {
					pfcpState.pdrList = append(pfcpState.pdrList, pdrList...)
					pfcpState.farList = append(pfcpState.farList, farList...)
					pfcpState.qerList = append(pfcpState.qerList, qerList...)
				}
			}
		}
	}

	for ip, pfcp := range pfcpPool {
		sessionContext, exist := smContext.PFCPContext[ip]
		remoteAddress := &net.UDPAddr{
			IP:   pfcp.nodeID.ResolveNodeIdToIp(),
			Port: int(pfcp.port),
		}

		if !exist || sessionContext.RemoteSEID == 0 {
			message.SendPfcpSessionEstablishmentRequest(
				remoteAddress, pfcp.nodeID, smContext, pfcp.pdrList, pfcp.farList, pfcp.qerList)
		} else {
			message.SendPfcpSessionModificationRequest(
				remoteAddress, pfcp.nodeID, smContext, pfcp.pdrList, pfcp.farList, pfcp.qerList)
		}
	}
}

func removeDataPath(smContext *context.SMContext, datapath *context.DataPath) {
	for curDPNode := datapath.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if curDPNode.DownLinkTunnel != nil && curDPNode.DownLinkTunnel.PDR != nil {
			for _, pdr := range curDPNode.DownLinkTunnel.PDR {
				pdr.State = context.RULE_REMOVE
				pdr.FAR.State = context.RULE_REMOVE
			}
		}
		if curDPNode.UpLinkTunnel != nil && curDPNode.UpLinkTunnel.PDR != nil {
			for _, pdr := range curDPNode.UpLinkTunnel.PDR {
				pdr.State = context.RULE_REMOVE
				pdr.FAR.State = context.RULE_REMOVE
			}
		}
	}
}

// UpdateDataPathToUPF update the datapath of the UPF
func UpdateDataPathToUPF(smContext *context.SMContext, oldDataPath, updateDataPath *context.DataPath) {
	if oldDataPath == nil {
		SendPFCPRule(smContext, updateDataPath)
		return
	} else {
		removeDataPath(smContext, oldDataPath)
		SendPFCPRule(smContext, updateDataPath)
	}
}
