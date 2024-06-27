// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"net"

	"github.com/omec-project/pfcp/pfcpType"
)

const (
	RULE_INITIAL RuleState = 0
	RULE_CREATE  RuleState = 1
	RULE_UPDATE  RuleState = 2
	RULE_REMOVE  RuleState = 3
)

type RuleState uint8

// Packet Detection Rule. Table 7.5.2.2-1
type PDR struct {
	OuterHeaderRemoval *OuterHeaderRemoval

	FAR *FAR
	URR *URR
	QER []*QER

	PDI        PDI
	State      RuleState
	PDRID      uint16
	Precedence uint32
}

// Packet Detection. 7.5.2.2-2
type PDI struct {
	LocalFTeid      *FTEID
	UEIPAddress     *UEIPAddress
	SDFFilter       *SDFFilter
	ApplicationID   string
	NetworkInstance string
	SourceInterface uint8
}

// F-TEID.
type FTEID struct {
	Flags uint8
	Teid  uint32
	V4    net.IP
	V6    net.IP
	Chid  uint8
}

// UE IP Address.
type UEIPAddress struct {
	Flags uint8
	V4    string
	V6    string
	V6d   uint8
	V6pl  uint8
}

// SDFFilter
type SDFFilter struct {
	Fd  string
	Ttc string
	Spi string
	Fl  string
	Fid uint32
}

// Outer Header Removal.
type OuterHeaderRemoval struct {
	Desc uint8
	Ext  uint8
}

// Forwarding Action Rule. 7.5.2.3-1
type FAR struct {
	ForwardingParameters *ForwardingParameters

	BAR   *BAR
	State RuleState
	FARID uint32

	ApplyAction *ApplyAction
}

type ApplyAction struct {
	Dupl bool
	Nocp bool
	Buff bool
	Forw bool
	Drop bool
}

// Forwarding Parameters. 7.5.2.3-2
type ForwardingParameters struct {
	OuterHeaderCreation  *OuterHeaderCreation
	PFCPSMReqFlags       *pfcpType.PFCPSMReqFlags
	ForwardingPolicyID   string
	NetworkInstance      string
	DestinationInterface uint8
}

type OuterHeaderCreation struct {
	Desc uint16
	Teid uint32
	V4   string
	V6   string
	Port uint16
	Ctag uint32
	Stag uint32
}

// Buffering Action Rule 7.5.2.6-1
type BAR struct {
	BARID uint8

	DownlinkDataNotificationDelay  pfcpType.DownlinkDataNotificationDelay
	SuggestedBufferingPacketsCount pfcpType.SuggestedBufferingPacketsCount

	State RuleState
}

// QoS Enhancement Rule
type QER struct {
	GateStatus *pfcpType.GateStatus
	MBR        *pfcpType.MBR
	GBR        *pfcpType.GBR

	State RuleState
	QFI   pfcpType.QFI
	QERID uint32
}

// Usage Report Rule
type URR struct{}

func (pdr PDR) String() string {
	return fmt.Sprintf("PDR:[PdrId:[%v], Precedence:[%v], PDI:[%v], OuterHeaderRem:[%v], Far:[%v], RuleState:[%v], QERS:[%v]]",
		pdr.PDRID, pdr.Precedence, pdr.PDI, pdr.OuterHeaderRemoval, pdr.FAR, pdr.State, pdr.QER)
}

func (pdi PDI) String() string {
	return fmt.Sprintf("PDI:[SourceInterface:[%v], LocalFteid:[%v], NetworkInstance:[%v], UEIpAddr:[%v], SdfFilter:[%v], AppId:[%v]]",
		pdi.SourceInterface, pdi.LocalFTeid, pdi.NetworkInstance, pdi.UEIPAddress, pdi.SDFFilter, pdi.ApplicationID)
}

func (far FAR) String() string {
	return fmt.Sprintf("FAR:[Id:[%v], ApplyAction:[%v], FrwdParam:[%v], BAR:[%v], State:[%v]]",
		far.FARID, ActionString(far.ApplyAction), far.ForwardingParameters, far.BAR, far.State)
}

func ActionString(act pfcpType.ApplyAction) string {
	return fmt.Sprintf("Action:[Dup:%v, Nocp:%v, Buff:%v, Forw:%v, Drop:%v]", act.Dupl, act.Nocp, act.Buff, act.Forw, act.Drop)
}

func (fp ForwardingParameters) String() string {
	return fmt.Sprintf("FwdParam:[DestIntf:[%v], NetworkInstance:[%v], OuterHeaderCreation:[%v], PFCPSMReqFlags:[%v], ForwardingPolicyID:[%v]]",
		fp.DestinationInterface, fp.NetworkInstance, fp.OuterHeaderCreation, fp.PFCPSMReqFlags, fp.ForwardingPolicyID)
}

func (bar BAR) String() string {
	return fmt.Sprintf("\nBAR:[Id:[%v], DDNDelay:[%v], BuffPktCount:[%v], RuleState:[%v]]",
		bar.BARID, bar.DownlinkDataNotificationDelay.DelayValue, bar.SuggestedBufferingPacketsCount.PacketCountValue, bar.State)
}

func (qer QER) String() string {
	return fmt.Sprintf("\nQER:[Id:[%v], QFI:[%v], MBR:[UL:[%v], DL:[%v]], Gate:[UL:[%v], DL:[%v]], RuleState:[%v]]",
		qer.QERID, qer.QFI, qer.MBR.ULMBR, qer.MBR.DLMBR, qer.GateStatus.ULGate, qer.GateStatus.DLGate, qer.State)
	// return fmt.Sprintf("\nQER:[Id:[%v], QFI:[%v], MBR:[UL:[%v], DL:[%v]], GBR:[UL:[%v], DL:[%v]], Gate:[UL:[%v], DL:[%v]], RuleState:[%v]] ",
	//	qer.QERID, qer.QFI, qer.MBR.ULMBR, qer.MBR.DLMBR, qer.GBR.ULGBR, qer.GBR.DLGBR, qer.GateStatus.ULGate, qer.GateStatus.DLGate, qer.State)
}
