// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package pfcp

import (
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/handler"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/message"
)

func Dispatch(msg *udp.Message) {
	// TODO: Add return status to all handlers
	msgType := msg.PfcpMessage.MessageType()
	switch msgType {
	case message.MsgTypeHeartbeatRequest:
		handler.HandlePfcpHeartbeatRequest(msg)
	case message.MsgTypeHeartbeatResponse:
		handler.HandlePfcpHeartbeatResponse(msg)
	case message.MsgTypePFDManagementRequest:
		handler.HandlePfcpPfdManagementRequest(msg)
	case message.MsgTypePFDManagementResponse:
		handler.HandlePfcpPfdManagementResponse(msg)
	case message.MsgTypeAssociationSetupRequest:
		handler.HandlePfcpAssociationSetupRequest(msg)
	case message.MsgTypeAssociationSetupResponse:
		handler.HandlePfcpAssociationSetupResponse(msg)
	case message.MsgTypeAssociationUpdateRequest:
		handler.HandlePfcpAssociationUpdateRequest(msg)
	case message.MsgTypeAssociationUpdateResponse:
		handler.HandlePfcpAssociationUpdateResponse(msg)
	case message.MsgTypeAssociationReleaseRequest:
		handler.HandlePfcpAssociationReleaseRequest(msg)
	case message.MsgTypeAssociationReleaseResponse:
		handler.HandlePfcpAssociationReleaseResponse(msg)
	case message.MsgTypeVersionNotSupportedResponse:
		handler.HandlePfcpVersionNotSupportedResponse(msg)
	case message.MsgTypeNodeReportRequest:
		handler.HandlePfcpNodeReportRequest(msg)
	case message.MsgTypeNodeReportResponse:
		handler.HandlePfcpNodeReportResponse(msg)
	case message.MsgTypeSessionSetDeletionRequest:
		handler.HandlePfcpSessionSetDeletionRequest(msg)
	case message.MsgTypeSessionSetDeletionResponse:
		handler.HandlePfcpSessionSetDeletionResponse(msg)
	case message.MsgTypeSessionEstablishmentResponse:
		handler.HandlePfcpSessionEstablishmentResponse(msg)
	case message.MsgTypeSessionModificationResponse:
		handler.HandlePfcpSessionModificationResponse(msg)
	case message.MsgTypeSessionDeletionResponse:
		handler.HandlePfcpSessionDeletionResponse(msg)
	case message.MsgTypeSessionReportRequest:
		handler.HandlePfcpSessionReportRequest(msg)
	case message.MsgTypeSessionReportResponse:
		handler.HandlePfcpSessionReportResponse(msg)
	default:
		logger.PfcpLog.Errorf("Unknown PFCP message type: %d", msgType)
		return
	}

	// stats
	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.PfcpMessage.MessageTypeName(), "In", "", "")
}
