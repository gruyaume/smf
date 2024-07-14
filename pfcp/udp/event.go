// Copyright 2024 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package udp

type EventType uint8

const (
	ReceiveResendRequest EventType = iota
	ReceiveValidResponse
)
