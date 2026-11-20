package setup

import (
	"fmt"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// V2IssuerRenewalRequestKind names the file `ratify-keys setup renew-issuer`
// writes. It carries only public data: the issuer it renews and the
// new authorization the root signed on the customer's machine.
const V2IssuerRenewalRequestKind = "ratify-issuer-renewal-request"

// V2IssuerRenewalRequest is the renewal request file.
type V2IssuerRenewalRequest struct {
	IssuerAuthorization []byte `json:"issuer_authorization"`
	IssuerKeyID         string `json:"issuer_key_id"`
	Kind                string `json:"kind"`
	OrganizationID      string `json:"organization_id"`
	Version             int    `json:"version"`
}

// ParseV2IssuerRenewalRequest checks a renewal request file at time now: a
// root-signed identity:delegate authorization for exactly the named issuer
// key, valid now, at most 90 days long. Verify then checks it is from the
// issuer's current root and extends the current authorization.
func ParseV2IssuerRenewalRequest(wire []byte, now int64) (V2IssuerRenewalRequest, *ratify.DelegationCertV2, error) {
	var request V2IssuerRenewalRequest
	if len(wire) < 2 || len(wire) > v2KeySetupMaxWire || decodeV2Strict(wire, &request) != nil {
		return request, nil, fmt.Errorf("the file is not a canonical ratify-keys issuer renewal request")
	}
	if request.Version != 1 || request.Kind != V2IssuerRenewalRequestKind {
		return request, nil, fmt.Errorf("the file is not a version 1 issuer renewal request")
	}
	if !v2ApproverUUID.MatchString(request.OrganizationID) || !v2HexID.MatchString(request.IssuerKeyID) {
		return request, nil, fmt.Errorf("the request does not name an organization and issuer key")
	}
	cert, err := ratify.DecodeDelegationCertV2(request.IssuerAuthorization)
	if err != nil {
		return request, nil, fmt.Errorf("the issuer authorization is not a delegation certificate")
	}
	if subjectID, err := V2KeyID(cert.SubjectPubKey); err != nil || subjectID != request.IssuerKeyID ||
		cert.SubjectID != request.IssuerKeyID {
		return request, nil, fmt.Errorf("the authorization is for another key; changing the issuer key is a rotation, not a renewal")
	}
	if _, err := VerifyV2SigningIssuerAuthorization(request.IssuerAuthorization, cert.IssuerID,
		request.IssuerKeyID, cert.IssuerPubKey, cert.SubjectPubKey, now); err != nil {
		return request, nil, fmt.Errorf("the issuer authorization is invalid: %v", err)
	}
	return request, cert, nil
}
