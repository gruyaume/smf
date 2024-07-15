// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package udp_test

import (
	"testing"

	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func TestGivenRequestWhenIsRequestThenReturnTrue(t *testing.T) {
	msg := message.NewAssociationReleaseRequest(
		1,
		ie.NewNodeID("1.1.1.1", "", ""),
	)

	if !udp.IsRequest(msg) {
		t.Errorf("Expected true, got false")
	}
}

func TestGivenResponseWhenIsRequestThenReturnFalse(t *testing.T) {
	msg := message.NewAssociationReleaseResponse(
		1,
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
	)

	if udp.IsRequest(msg) {
		t.Errorf("Expected false, got true")
	}
}
