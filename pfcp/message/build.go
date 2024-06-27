// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"net"

	"github.com/omec-project/pfcp"
	"github.com/omec-project/pfcp/pfcpType"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// BuildPfcpHeartbeatRequest shall trigger hearbeat request to all Attached UPFs
func BuildPfcpHeartbeatRequest() (pfcp.HeartbeatRequest, error) {
	msg := pfcp.HeartbeatRequest{}

	msg.RecoveryTimeStamp = &pfcpType.RecoveryTimeStamp{
		RecoveryTimeStamp: udp.ServerStartTime,
	}

	return msg, nil
}

func BuildPfcpAssociationSetupRequest() (pfcp.PFCPAssociationSetupRequest, error) {
	msg := pfcp.PFCPAssociationSetupRequest{}

	msg.NodeID = &context.SMF_Self().CPNodeID

	msg.RecoveryTimeStamp = &pfcpType.RecoveryTimeStamp{
		RecoveryTimeStamp: udp.ServerStartTime,
	}

	msg.CPFunctionFeatures = &pfcpType.CPFunctionFeatures{
		SupportedFeatures: 0,
	}

	return msg, nil
}

func BuildPfcpAssociationSetupResponse(cause pfcpType.Cause) (pfcp.PFCPAssociationSetupResponse, error) {
	msg := pfcp.PFCPAssociationSetupResponse{}

	msg.NodeID = &context.SMF_Self().CPNodeID

	msg.Cause = &cause

	msg.RecoveryTimeStamp = &pfcpType.RecoveryTimeStamp{
		RecoveryTimeStamp: udp.ServerStartTime,
	}

	msg.CPFunctionFeatures = &pfcpType.CPFunctionFeatures{
		SupportedFeatures: 0,
	}

	return msg, nil
}

func BuildPfcpAssociationReleaseRequest() (pfcp.PFCPAssociationReleaseRequest, error) {
	msg := pfcp.PFCPAssociationReleaseRequest{}

	msg.NodeID = &context.SMF_Self().CPNodeID

	return msg, nil
}

func BuildPfcpAssociationReleaseResponse(cause pfcpType.Cause) (pfcp.PFCPAssociationReleaseResponse, error) {
	msg := pfcp.PFCPAssociationReleaseResponse{}

	msg.NodeID = &context.SMF_Self().CPNodeID

	msg.Cause = &cause

	return msg, nil
}

func pdrToCreatePDR(pdr *context.PDR) *ie.IE {
	ies := make([]*ie.IE, 0)

	ies = append(ies, ie.NewPDRID(pdr.PDRID))
	ies = append(ies, ie.NewPrecedence(pdr.Precedence))

	pdiElements := []*ie.IE{
		ie.NewSourceInterface(pdr.PDI.SourceInterface),
		ie.NewFTEID(
			pdr.PDI.LocalFTeid.Flags,
			pdr.PDI.LocalFTeid.Teid,
			pdr.PDI.LocalFTeid.V4,
			pdr.PDI.LocalFTeid.V6,
			pdr.PDI.LocalFTeid.Chid,
		),
		ie.NewNetworkInstance(pdr.PDI.NetworkInstance),
		ie.NewUEIPAddress(
			pdr.PDI.UEIPAddress.Flags,
			pdr.PDI.UEIPAddress.V4,
			pdr.PDI.UEIPAddress.V6,
			pdr.PDI.UEIPAddress.V6d,
			pdr.PDI.UEIPAddress.V6pl,
		),
	}

	if pdr.PDI.ApplicationID != "" {
		pdiElements = append(pdiElements, ie.NewApplicationID(pdr.PDI.ApplicationID))
	}

	if pdr.PDI.SDFFilter != nil {
		pdiElements = append(pdiElements, ie.NewSDFFilter(
			pdr.PDI.SDFFilter.Fd,
			pdr.PDI.SDFFilter.Ttc,
			pdr.PDI.SDFFilter.Spi,
			pdr.PDI.SDFFilter.Fl,
			pdr.PDI.SDFFilter.Fid,
		))
	}

	pdiIE := ie.NewPDI(pdiElements...)

	ies = append(ies, pdiIE)
	ies = append(ies, ie.NewOuterHeaderRemoval(pdr.OuterHeaderRemoval.Desc, pdr.OuterHeaderRemoval.Ext))
	ies = append(ies, ie.NewFARID(pdr.FAR.FARID))

	qerIEs := make([]*ie.IE, 0)
	for _, qer := range pdr.QER {
		if qer != nil {
			qerIEs = append(qerIEs, ie.NewQERID(qer.QERID))
		}
	}

	ies = append(ies, qerIEs...)

	createPDR := ie.NewCreatePDR(ies...)

	return createPDR
}

func farToCreateFAR(far *context.FAR) *ie.IE {
	ies := make([]*ie.IE, 0)

	ies = append(ies, ie.NewFARID(far.FARID))

	applyActionFlags := make([]uint8, 0)
	if far.ApplyAction.Dupl {
		applyActionFlags = append(applyActionFlags, 0x01)
	}
	if far.ApplyAction.Nocp {
		applyActionFlags = append(applyActionFlags, 0x02)
	}
	if far.ApplyAction.Buff {
		applyActionFlags = append(applyActionFlags, 0x04)
	}
	if far.ApplyAction.Forw {
		applyActionFlags = append(applyActionFlags, 0x08)
	}
	if far.ApplyAction.Drop {
		applyActionFlags = append(applyActionFlags, 0x10)
	}

	applyAction := ie.NewApplyAction(applyActionFlags...)

	ies = append(ies, applyAction)

	if far.BAR != nil {
		ies = append(ies, ie.NewBARID(far.BAR.BARID))
	}

	if far.ForwardingParameters != nil {
		forwardingParametersIes := make([]*ie.IE, 0)
		forwardingParametersIes = append(forwardingParametersIes, ie.NewDestinationInterface(far.ForwardingParameters.DestinationInterface))
		forwardingParametersIes = append(forwardingParametersIes, ie.NewNetworkInstance(far.ForwardingParameters.NetworkInstance))
		forwardingParametersIes = append(forwardingParametersIes, ie.NewOuterHeaderCreation(
			far.ForwardingParameters.OuterHeaderCreation.Desc,
			far.ForwardingParameters.OuterHeaderCreation.Teid,
			far.ForwardingParameters.OuterHeaderCreation.V4,
			far.ForwardingParameters.OuterHeaderCreation.V6,
			far.ForwardingParameters.OuterHeaderCreation.Port,
			far.ForwardingParameters.OuterHeaderCreation.Ctag,
			far.ForwardingParameters.OuterHeaderCreation.Stag,
		))

		if far.ForwardingParameters.ForwardingPolicyID != "" {
			forwardingPolicy := ie.NewForwardingPolicy(far.ForwardingParameters.ForwardingPolicyID)
			forwardingParametersIes = append(forwardingParametersIes, forwardingPolicy)
		}

		ies = append(ies, ie.NewForwardingParameters())

	}

	createFAR := ie.NewCreateFAR(ies...)

	return createFAR
}

func barToCreateBAR(bar *context.BAR) *pfcp.CreateBAR {
	createBAR := new(pfcp.CreateBAR)

	createBAR.BARID = new(pfcpType.BARID)
	createBAR.BARID.BarIdValue = bar.BARID

	createBAR.DownlinkDataNotificationDelay = new(pfcpType.DownlinkDataNotificationDelay)

	// createBAR.SuggestedBufferingPacketsCount = new(pfcpType.SuggestedBufferingPacketsCount)

	return createBAR
}

func qerToCreateQER(qer *context.QER) *pfcp.CreateQER {
	createQER := new(pfcp.CreateQER)

	createQER.QERID = new(pfcpType.QERID)
	createQER.QERID.QERID = qer.QERID
	createQER.GateStatus = qer.GateStatus

	createQER.QoSFlowIdentifier = &qer.QFI
	createQER.MaximumBitrate = qer.MBR
	createQER.GuaranteedBitrate = qer.GBR

	return createQER
}

func pdrToUpdatePDR(pdr *context.PDR) *pfcp.UpdatePDR {
	updatePDR := new(pfcp.UpdatePDR)

	updatePDR.PDRID = new(pfcpType.PacketDetectionRuleID)
	updatePDR.PDRID.RuleId = pdr.PDRID

	updatePDR.Precedence = new(pfcpType.Precedence)
	updatePDR.Precedence.PrecedenceValue = pdr.Precedence

	updatePDR.PDI = &pfcp.PDI{
		SourceInterface: &pdr.PDI.SourceInterface,
		LocalFTEID:      pdr.PDI.LocalFTeid,
		NetworkInstance: &pdr.PDI.NetworkInstance,
		UEIPAddress:     pdr.PDI.UEIPAddress,
	}

	if pdr.PDI.ApplicationID != "" {
		updatePDR.PDI.ApplicationID = &pfcpType.ApplicationID{
			ApplicationIdentifier: []byte(pdr.PDI.ApplicationID),
		}
	}

	if pdr.PDI.SDFFilter != nil {
		updatePDR.PDI.SDFFilter = pdr.PDI.SDFFilter
	}

	updatePDR.OuterHeaderRemoval = pdr.OuterHeaderRemoval

	updatePDR.FARID = &pfcpType.FARID{
		FarIdValue: pdr.FAR.FARID,
	}

	for _, qer := range pdr.QER {
		if qer != nil {
			updatePDR.QERID = append(updatePDR.QERID, &pfcpType.QERID{
				QERID: qer.QERID,
			})
		}
	}

	return updatePDR
}

func farToUpdateFAR(far *context.FAR) *pfcp.UpdateFAR {
	updateFAR := new(pfcp.UpdateFAR)

	updateFAR.FARID = new(pfcpType.FARID)
	updateFAR.FARID.FarIdValue = far.FARID

	if far.BAR != nil {
		updateFAR.BARID = new(pfcpType.BARID)
		updateFAR.BARID.BarIdValue = far.BAR.BARID
	}

	updateFAR.ApplyAction = new(pfcpType.ApplyAction)
	updateFAR.ApplyAction.Forw = far.ApplyAction.Forw
	updateFAR.ApplyAction.Buff = far.ApplyAction.Buff
	updateFAR.ApplyAction.Nocp = far.ApplyAction.Nocp
	updateFAR.ApplyAction.Dupl = far.ApplyAction.Dupl
	updateFAR.ApplyAction.Drop = far.ApplyAction.Drop

	if far.ForwardingParameters != nil {
		updateFAR.UpdateForwardingParameters = new(pfcp.UpdateForwardingParametersIEInFAR)
		updateFAR.UpdateForwardingParameters.DestinationInterface = &far.ForwardingParameters.DestinationInterface
		updateFAR.UpdateForwardingParameters.NetworkInstance = &far.ForwardingParameters.NetworkInstance
		updateFAR.UpdateForwardingParameters.OuterHeaderCreation = far.ForwardingParameters.OuterHeaderCreation
		if far.ForwardingParameters.PFCPSMReqFlags != nil {
			updateFAR.UpdateForwardingParameters.PFCPSMReqFlags = far.ForwardingParameters.PFCPSMReqFlags
			// reset original far sndem flag
			far.ForwardingParameters.PFCPSMReqFlags = nil
		}

		if far.ForwardingParameters.ForwardingPolicyID != "" {
			updateFAR.UpdateForwardingParameters.ForwardingPolicy = new(pfcpType.ForwardingPolicy)
			updateFAR.UpdateForwardingParameters.ForwardingPolicy.ForwardingPolicyIdentifierLength = uint8(len(far.ForwardingParameters.ForwardingPolicyID))
			updateFAR.UpdateForwardingParameters.ForwardingPolicy.ForwardingPolicyIdentifier = []byte(far.ForwardingParameters.ForwardingPolicyID)
		}
	}

	return updateFAR
}

func BuildPfcpSessionEstablishmentRequest(
	upNodeID pfcpType.NodeID,
	smContext *context.SMContext,
	pdrList []*context.PDR,
	farList []*context.FAR,
	barList []*context.BAR,
	qerList []*context.QER,
	seid uint64,
	seq uint32,
	pri uint8,
) (*message.SessionEstablishmentRequest, error) {

	ies := make([]*ie.IE, 0)

	ies = append(ies, ie.NewNodeID(context.SMF_Self().CPNodeID.Ipv4, context.SMF_Self().CPNodeID.Ipv6, context.SMF_Self().CPNodeID.Fqdn))

	var cpFSEID *ie.IE
	if context.SMF_Self().CPNodeID.Ipv4 != "" {
		localSEID := smContext.PFCPContext[context.SMF_Self().CPNodeID.Ipv4].LocalSEID
		cpFSEID = ie.NewFSEID(localSEID, net.IP(context.SMF_Self().CPNodeID.Ipv4), nil)
	} else {
		localSEID := smContext.PFCPContext[context.SMF_Self().CPNodeID.Ipv6].LocalSEID
		cpFSEID = ie.NewFSEID(localSEID, nil, net.IP(context.SMF_Self().CPNodeID.Ipv6))
	}
	ies = append(ies, cpFSEID)

	for _, pdr := range pdrList {
		if pdr.State == context.RULE_INITIAL {
			ies = append(ies, pdrToCreatePDR(pdr))
		}
		pdr.State = context.RULE_CREATE
	}

	for _, far := range farList {
		if far.State == context.RULE_INITIAL {
			ies = append(ies, farToCreateFAR(far))
		}
		far.State = context.RULE_CREATE
	}

	for _, bar := range barList {
		if bar.State == context.RULE_INITIAL {
			ies = append(ies, barToCreateBAR(bar))
		}
		bar.State = context.RULE_CREATE
	}

	for _, qer := range qerList {
		if qer.State == context.RULE_INITIAL {
			ies = append(ies, qerToCreateQER(qer))
		}
		qer.State = context.RULE_CREATE
	}

	ies = append(ies, ie.NewPDNType(ie.PDNTypeIPv4))
	msg := message.NewSessionEstablishmentRequest(1, 1, seid, seq, pri, ies...)

	return msg, nil
}

func BuildPfcpSessionEstablishmentResponse() (pfcp.PFCPSessionEstablishmentResponse, error) {
	msg := pfcp.PFCPSessionEstablishmentResponse{}

	msg.NodeID = &context.SMF_Self().CPNodeID

	msg.Cause = &pfcpType.Cause{
		CauseValue: pfcpType.CauseRequestAccepted,
	}

	msg.OffendingIE = &pfcpType.OffendingIE{
		TypeOfOffendingIe: 12345,
	}

	msg.UPFSEID = &pfcpType.FSEID{
		V4:          true,
		V6:          false, //;
		Seid:        123456789123456789,
		Ipv4Address: net.ParseIP("192.168.1.1").To4(),
	}

	msg.CreatedPDR = &pfcp.CreatedPDR{
		PDRID: &pfcpType.PacketDetectionRuleID{
			RuleId: 256,
		},
		LocalFTEID: &pfcpType.FTEID{
			Chid:        false,
			Ch:          false,
			V6:          false,
			V4:          true,
			Teid:        12345,
			Ipv4Address: net.ParseIP("192.168.1.1").To4(),
		},
	}

	return msg, nil
}

// TODO: Replace dummy value in PFCP message
func BuildPfcpSessionModificationRequest(
	upNodeID pfcpType.NodeID,
	smContext *context.SMContext,
	pdrList []*context.PDR,
	farList []*context.FAR,
	barList []*context.BAR,
	qerList []*context.QER,
) (pfcp.PFCPSessionModificationRequest, error) {
	msg := pfcp.PFCPSessionModificationRequest{}

	msg.UpdatePDR = make([]*pfcp.UpdatePDR, 0, 2)
	msg.UpdateFAR = make([]*pfcp.UpdateFAR, 0, 2)

	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()

	localSEID := smContext.PFCPContext[nodeIDtoIP].LocalSEID

	msg.CPFSEID = &pfcpType.FSEID{
		V4:          true,
		V6:          false,
		Seid:        localSEID,
		Ipv4Address: context.SMF_Self().CPNodeID.NodeIdValue,
	}

	for _, pdr := range pdrList {
		switch pdr.State {
		case context.RULE_INITIAL:
			msg.CreatePDR = append(msg.CreatePDR, pdrToCreatePDR(pdr))
		case context.RULE_UPDATE:
			msg.UpdatePDR = append(msg.UpdatePDR, pdrToUpdatePDR(pdr))
		case context.RULE_REMOVE:
			msg.RemovePDR = append(msg.RemovePDR, &pfcp.RemovePDR{
				PDRID: &pfcpType.PacketDetectionRuleID{
					RuleId: pdr.PDRID,
				},
			})
		}
		pdr.State = context.RULE_CREATE
	}

	for _, far := range farList {
		switch far.State {
		case context.RULE_INITIAL:
			msg.CreateFAR = append(msg.CreateFAR, farToCreateFAR(far))
		case context.RULE_UPDATE:
			msg.UpdateFAR = append(msg.UpdateFAR, farToUpdateFAR(far))
		case context.RULE_REMOVE:
			msg.RemoveFAR = append(msg.RemoveFAR, &pfcp.RemoveFAR{
				FARID: &pfcpType.FARID{
					FarIdValue: far.FARID,
				},
			})
		}
		far.State = context.RULE_CREATE
	}

	for _, bar := range barList {
		switch bar.State {
		case context.RULE_INITIAL:
			msg.CreateBAR = append(msg.CreateBAR, barToCreateBAR(bar))
		}
	}

	for _, qer := range qerList {
		switch qer.State {
		case context.RULE_INITIAL:
			msg.CreateQER = append(msg.CreateQER, qerToCreateQER(qer))
		}
		qer.State = context.RULE_CREATE
	}

	return msg, nil
}

// TODO: Replace dummy value in PFCP message
func BuildPfcpSessionModificationResponse() (pfcp.PFCPSessionModificationResponse, error) {
	msg := pfcp.PFCPSessionModificationResponse{}

	msg.Cause = &pfcpType.Cause{
		CauseValue: pfcpType.CauseRequestAccepted,
	}

	msg.OffendingIE = &pfcpType.OffendingIE{
		TypeOfOffendingIe: 12345,
	}

	msg.CreatedPDR = &pfcp.CreatedPDR{
		PDRID: &pfcpType.PacketDetectionRuleID{
			RuleId: 256,
		},
		LocalFTEID: &pfcpType.FTEID{
			Chid:        false,
			Ch:          false,
			V6:          false,
			V4:          true,
			Teid:        12345,
			Ipv4Address: net.ParseIP("192.168.1.1").To4(),
		},
	}

	return msg, nil
}

func BuildPfcpSessionDeletionRequest(
	upNodeID pfcpType.NodeID,
	smContext *context.SMContext,
) (pfcp.PFCPSessionDeletionRequest, error) {
	msg := pfcp.PFCPSessionDeletionRequest{}

	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()

	localSEID := smContext.PFCPContext[nodeIDtoIP].LocalSEID

	msg.CPFSEID = &pfcpType.FSEID{
		V4:          true,
		V6:          false,
		Seid:        localSEID,
		Ipv4Address: context.SMF_Self().CPNodeID.NodeIdValue,
	}
	return msg, nil
}

// TODO: Replace dummy value in PFCP message
func BuildPfcpSessionDeletionResponse() (pfcp.PFCPSessionDeletionResponse, error) {
	msg := pfcp.PFCPSessionDeletionResponse{}

	msg.Cause = &pfcpType.Cause{
		CauseValue: pfcpType.CauseRequestAccepted,
	}

	msg.OffendingIE = &pfcpType.OffendingIE{
		TypeOfOffendingIe: 12345,
	}

	return msg, nil
}

func BuildPfcpSessionReportResponse(cause pfcpType.Cause, pfcpSRflag pfcpType.PFCPSRRspFlags) (pfcp.PFCPSessionReportResponse, error) {
	msg := pfcp.PFCPSessionReportResponse{}

	msg.Cause = &cause

	if pfcpSRflag.Drobu {
		msg.SxSRRspFlags = &pfcpType.PFCPSRRspFlags{Drobu: true}
	}

	return msg, nil
}
