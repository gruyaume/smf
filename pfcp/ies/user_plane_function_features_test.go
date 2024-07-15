// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package ies_test

import (
	"testing"

	"github.com/omec-project/smf/pfcp/ies"
	"github.com/wmnsk/go-pfcp/ie"
)

func TestUnmarshallUserPlaneFunctionFeaturesEmpty(t *testing.T) {
	userplaneIE := ie.NewUPFunctionFeatures()
	functionFeatures, err := ies.UnmarshallUserPlaneFunctionFeatures(userplaneIE.Payload)
	if err != nil {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}

	if functionFeatures == nil {
		t.Fatalf("Error unmarshalling UE IP Information: %v", err)
	}

	if functionFeatures.SupportedFeatures != 0 {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}

	if functionFeatures.SupportedFeatures1 != 0 {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}

	if functionFeatures.SupportedFeatures2 != 0 {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}
}
