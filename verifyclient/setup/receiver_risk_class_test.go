package setup

import (
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Receivers may mark an operation standard or high; any other risk class is
// unimplemented and the configuration is refused.
func TestV2ReceiverOperationRiskClasses(t *testing.T) {
	pub, _, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := V2KeyID(pub)
	content := func(risk string) V2ReceiverConfigContent {
		return V2ReceiverConfigContent{
			Anchors: []V2TrustAnchor{{PublicKey: pub, RootID: rootID}}, ConfigSignerKey: pub,
			IssuerStatusKeys: []V2IssuerStatusKey{{Epoch: 1, IssuerID: rootID, StatusKey: pub}},
			Operations:       []V2ReceiverOperation{{Action: "delete", OperationID: "files", RequiredScope: "data:delete", RiskClass: risk}},
			ReceiverID:       "receiver-1", Schema: v2ReceiverConfigSchema, StatusPolicy: V2StatusPolicy{MaxListLifetimeSeconds: 600, MaxStatusAgeSeconds: 300},
			VerifyCode: v2VerifyCodeReceiverConfig, Version: v2TrustProfileVersion, WorkspaceID: "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
		}
	}
	for risk, ok := range map[string]bool{"standard": true, "high": true, "critical": false, "": false, "HIGH": false} {
		if err := validateV2ReceiverConfigContent(content(risk)); (err == nil) != ok {
			t.Errorf("risk class %q: err %v, want accepted=%v", risk, err, ok)
		}
	}
}

// A receiver configuration must not promise an approval that no valid
// Protocol v2 delegation certificate can satisfy.
func TestV2ReceiverOperationRequiresProtocolScope(t *testing.T) {
	pub, _, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := V2KeyID(pub)
	content := V2ReceiverConfigContent{
		Anchors: []V2TrustAnchor{{PublicKey: pub, RootID: rootID}}, ConfigSignerKey: pub,
		IssuerStatusKeys: []V2IssuerStatusKey{{Epoch: 1, IssuerID: rootID, StatusKey: pub}},
		Operations:       []V2ReceiverOperation{{Action: "send", OperationID: "payment.send", RiskClass: "standard"}},
		ReceiverID:       "receiver-1", Schema: v2ReceiverConfigSchema, StatusPolicy: V2StatusPolicy{MaxListLifetimeSeconds: 600, MaxStatusAgeSeconds: 300},
		VerifyCode: v2VerifyCodeReceiverConfig, Version: v2TrustProfileVersion, WorkspaceID: "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
	}
	for scope, accepted := range map[string]bool{"payment:send": false, "custom:ratify:payment-send": true, "data:read": true} {
		content.Operations[0].RequiredScope = scope
		if err := validateV2ReceiverConfigContent(content); (err == nil) != accepted {
			t.Errorf("scope %q: err %v, want accepted=%t", scope, err, accepted)
		}
	}
}
