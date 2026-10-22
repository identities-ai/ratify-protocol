package ratify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
)

// Authenticated status at the verifier boundary (SPEC-v2 §6.5).
//
// The status provider never supplies a StatusResult. For each distinct issuer
// in the verified chain, in ascending byte order of issuer ID, the verifier:
//  1. loads the committed SecurityJournalV2 at its anchored head and requires
//     the caller-authenticated status key (StatusKeys) to equal the journal's
//     current epoch binding for the issuer;
//  2. checks role separation by complete key ID and both component digests;
//  3. asks the provider for a bounded batch of signed lists and pushes;
//  4. decodes every object and verifies it under the selected key (any
//     failure rejects the whole batch);
//  5. applies the batch, sorted by sequence, then code, then
//     StatusEvidenceDigest, as one journal transition committed by
//     compare-and-swap against the head loaded in step 1; on a conflict it
//     reloads, rechecks steps 1 and 2, and reapplies the same batch exactly
//     once more;
//  6. derives each CertificateRef result from the committed journal state.
//
// A missing binding, unanchored or unmigrated journal, role violation,
// provider error/timeout/panic, malformed/oversized/unauthenticated batch,
// reducer rejection, store failure or compare-and-swap conflict makes every
// reference of that issuer indeterminate/unavailable with no evidence. These
// are terminal status outcomes; they do not interrupt the claim. If the
// caller's context ends during the stage, nothing is committed and the
// verifier returns V2StageEvaluating with evaluation_cancelled.

// V2StatusKeyConfig is the caller-authenticated status-key binding for one
// issuer. It must equal the binding retained in the security journal at that
// epoch, and the epoch must be the issuer's current journal epoch.
type V2StatusKeyConfig struct {
	Epoch uint64
	Key   HybridPublicKey
}

// V2StatusEvidenceRequest is what the verifier asks a status provider for. It
// is chosen by the verifier from authenticated configuration, never from the
// proof. Refs are the issuer's CertificateRefs in chain order.
type V2StatusEvidenceRequest struct {
	IssuerID       string
	StatusKeyEpoch uint64
	StatusKeyID    string
	Refs           []CertificateRefV2
}

// V2StatusEvidenceObject is one signed status object exactly as received.
// ObjectType is 0x0003 (revocation list) or 0x0005 (revocation push).
type V2StatusEvidenceObject struct {
	ObjectType uint16
	Wire       []byte
}

// V2StatusEvidenceBatch is a provider's bounded response for one issuer. An
// empty batch is valid: the result then comes from retained journal state.
type V2StatusEvidenceBatch struct {
	Objects []V2StatusEvidenceObject
}

type v2StatusStageResult struct {
	assessment V2StatusAssessment
	cancelled  error
	queries    int
}

type v2VerifiedStatusObject struct {
	code     uint16
	sequence int64
	digest   []byte
	list     *RevocationListV2
	push     *RevocationPushV2
}

// runV2StatusStage executes the status stage for every CertificateRef check.
func runV2StatusStage(ctx context.Context, bundle *ProofBundleV2, checks []V2CertificateStatusCheck, req V2VerifyRequest, cb V2VerifyCallbacks, now int64) v2StatusStageResult {
	issuerIDs := make([]string, 0, len(checks))
	refsByIssuer := map[string][]CertificateRefV2{}
	for _, check := range checks {
		if _, seen := refsByIssuer[check.IssuerID]; !seen {
			issuerIDs = append(issuerIDs, check.IssuerID)
		}
		refsByIssuer[check.IssuerID] = append(refsByIssuer[check.IssuerID], CertificateRefV2{IssuerID: check.IssuerID, CertID: check.CertID})
	}
	sort.Strings(issuerIDs)
	results := make([]RevocationStatusResultV2, len(checks))
	for i := range results {
		results[i] = unavailableV2StatusResult()
	}
	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
	queries := 0
	for _, issuerID := range issuerIDs {
		if err := ctx.Err(); err != nil {
			return v2StatusStageResult{cancelled: err, queries: queries}
		}
		config, configured := req.StatusKeys[issuerID]
		if !configured || cb.StatusJournal == nil || cb.StatusEvidence == nil {
			continue
		}
		// 1. Anchored journal and current epoch binding.
		var current SecurityJournalV2
		if err := callV2JournalSafely(func() (err error) { current, err = loadAnchoredSecurityJournalV2(ctx, cb.StatusJournal); return err }); err != nil {
			if ctx.Err() != nil {
				return v2StatusStageResult{cancelled: ctx.Err(), queries: queries}
			}
			continue
		}
		// 2. Role separation.
		if err := checkV2StatusRoleSeparation(&current, issuerID, config, bundle); err != nil {
			continue
		}
		statusKeyID, _ := keyIDV2(config.Key)
		// 3. Provider.
		queries++
		batch, err := callV2StatusProvider(ctx, cb.StatusEvidence, V2StatusEvidenceRequest{
			IssuerID: issuerID, StatusKeyEpoch: config.Epoch, StatusKeyID: statusKeyID, Refs: append([]CertificateRefV2(nil), refsByIssuer[issuerID]...),
		})
		if err != nil {
			if ctx.Err() != nil {
				return v2StatusStageResult{cancelled: ctx.Err(), queries: queries}
			}
			continue
		}
		// 4. Authenticate.
		objects, err := verifyV2StatusEvidenceBatch(batch, issuerID, config.Key)
		if err != nil {
			continue
		}
		// 5. Apply as one transition against the loaded head. On a
		// compare-and-swap conflict, reload the anchored journal, repeat the
		// binding and role-separation checks, and reapply the same batch
		// exactly once more (no second provider call); a second conflict or
		// any other failure makes the issuer unavailable.
		var committed SecurityJournalV2
		applied := false
		for attempt := 0; attempt < 2 && !applied; attempt++ {
			if attempt > 0 {
				if err := callV2JournalSafely(func() (err error) { current, err = loadAnchoredSecurityJournalV2(ctx, cb.StatusJournal); return err }); err != nil {
					break
				}
				if err := checkV2StatusRoleSeparation(&current, issuerID, config, bundle); err != nil {
					break
				}
			}
			err := callV2JournalSafely(func() (err error) {
				committed, err = applyV2StatusBatchToJournal(ctx, cb.StatusJournal, current, issuerID, config, objects, req.StatusPolicy, now)
				return err
			})
			if err == nil {
				applied = true
			} else if !errors.Is(err, ErrSecurityJournalConflictV2) {
				break
			}
		}
		if ctx.Err() != nil {
			return v2StatusStageResult{cancelled: ctx.Err(), queries: queries}
		}
		if !applied {
			continue
		}
		// 6. Derive from committed state.
		for _, binding := range committed.StatusKeyHistory {
			if binding.IssuerID == issuerID {
				roles.StatusKeyIssuers[binding.StatusKeyID] = issuerID
			}
		}
		roles.CurrentStatusKeyIDs[issuerID] = statusKeyID
		for i, check := range checks {
			if check.IssuerID != issuerID {
				continue
			}
			result, err := RevocationStatusForCertV2(committed.StatusByIssuer[issuerID], issuerID, check.CertID, config.Epoch, config.Key, req.StatusPolicy, now)
			if err != nil {
				result = unavailableV2StatusResult()
			}
			results[i] = result
		}
	}
	assessment, err := aggregateCertificateStatusV2(checks, results, roles, true)
	if err != nil {
		assessment = V2StatusAssessment{Assessment: "unavailable", Reason: "status_unavailable", Evidence: []StatusEvidenceEntryV2{}}
	}
	return v2StatusStageResult{assessment: assessment, queries: queries}
}

func unavailableV2StatusResult() RevocationStatusResultV2 {
	return RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}
}

func callV2StatusProvider(ctx context.Context, provider func(context.Context, V2StatusEvidenceRequest) (V2StatusEvidenceBatch, error), req V2StatusEvidenceRequest) (batch V2StatusEvidenceBatch, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			batch, err = V2StatusEvidenceBatch{}, fmt.Errorf("v2 status provider panicked: %v", recovered)
		}
	}()
	return provider(ctx, req)
}

// verifyV2StatusEvidenceBatch decodes and authenticates every object before
// any is applied, and returns them in the deterministic application order:
// ascending sequence, then object type code (list before push), then evidence
// digest bytes.
func verifyV2StatusEvidenceBatch(batch V2StatusEvidenceBatch, issuerID string, key HybridPublicKey) ([]v2VerifiedStatusObject, error) {
	if len(batch.Objects) > MaxStatusEvidenceBatchObjectsV2 {
		return nil, fmt.Errorf("v2 status batch exceeds %d objects", MaxStatusEvidenceBatchObjectsV2)
	}
	if v2StatusEvidenceBatchEncodedLength(batch) > MaxStatusEvidenceBatchBytesV2 {
		return nil, fmt.Errorf("v2 status batch exceeds %d bytes", MaxStatusEvidenceBatchBytesV2)
	}
	out := make([]v2VerifiedStatusObject, 0, len(batch.Objects))
	for _, object := range batch.Objects {
		switch object.ObjectType {
		case uint16(v2RevocationList):
			list, err := DecodeRevocationListV2(object.Wire)
			if err != nil {
				return nil, err
			}
			if err := VerifyRevocationListV2Signature(list, issuerID, key); err != nil {
				return nil, err
			}
			digest, err := StatusEvidenceDigest(object.ObjectType, list)
			if err != nil {
				return nil, err
			}
			out = append(out, v2VerifiedStatusObject{code: object.ObjectType, sequence: list.Sequence, digest: digest, list: list})
		case uint16(v2RevocationPush):
			push, err := DecodeRevocationPushV2(object.Wire)
			if err != nil {
				return nil, err
			}
			if err := VerifyRevocationPushV2Signature(push, issuerID, key); err != nil {
				return nil, err
			}
			digest, err := StatusEvidenceDigest(object.ObjectType, push)
			if err != nil {
				return nil, err
			}
			out = append(out, v2VerifiedStatusObject{code: object.ObjectType, sequence: push.Sequence, digest: digest, push: push})
		default:
			return nil, fmt.Errorf("v2 status batch contains unsupported object type 0x%04x", object.ObjectType)
		}
	}
	slices.SortFunc(out, func(a, b v2VerifiedStatusObject) int {
		switch {
		case a.sequence != b.sequence:
			if a.sequence < b.sequence {
				return -1
			}
			return 1
		case a.code != b.code:
			if a.code < b.code {
				return -1
			}
			return 1
		default:
			return bytes.Compare(a.digest, b.digest)
		}
	})
	return out, nil
}

// applyV2StatusBatchToJournal applies one issuer's authenticated batch to
// the loaded journal and commits it by compare-and-swap against the loaded
// head. A no-op batch returns the loaded journal unchanged.
func applyV2StatusBatchToJournal(ctx context.Context, store SecurityJournalStoreV2, current SecurityJournalV2, issuerID string, config V2StatusKeyConfig, objects []v2VerifiedStatusObject, policy RevocationStatusPolicyV2, now int64) (SecurityJournalV2, error) {
	next, err := cloneSecurityJournalV2(current)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	state := next.StatusByIssuer[issuerID]
	for _, object := range objects {
		if object.list != nil {
			state, err = ApplyRevocationListV2(state, object.list, issuerID, config.Epoch, config.Key, policy, now)
		} else {
			state, err = ApplyRevocationPushV2(state, object.push, issuerID, config.Epoch, config.Key, policy, now)
		}
		if err != nil {
			return SecurityJournalV2{}, err
		}
	}
	next.StatusByIssuer[issuerID] = state
	return commitSecurityJournalTransitionV2(ctx, store, current, next)
}

func callV2JournalSafely(f func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("v2 status journal panicked: %v", recovered)
		}
	}()
	return f()
}

// checkV2StatusRoleSeparation enforces SPEC-v2 §5.4 and §6.5 permanent role
// separation before an issuer's results are used: the configured status key
// must be the issuer's current journal epoch binding; its global role history
// entry must be exactly the status role; and neither its complete key ID nor
// either component key may equal the key ID or either component of any other
// journal role or of any key in the proof (issuers, subjects, agent), or the
// proof's verifier ID.
func checkV2StatusRoleSeparation(journal *SecurityJournalV2, issuerID string, config V2StatusKeyConfig, bundle *ProofBundleV2) error {
	if err := requireJournalStatusKeyV2(journal, issuerID, config.Epoch, config.Key); err != nil {
		return err
	}
	status, err := keyRoleBindingV2("status", config.Key)
	if err != nil {
		return err
	}
	recorded := false
	overlaps := func(other KeyRoleBindingV2) bool {
		components := []string{status.Ed25519Digest, status.MLDSA65Digest}
		return other.KeyID == status.KeyID || slices.Contains(components, other.Ed25519Digest) || slices.Contains(components, other.MLDSA65Digest)
	}
	for _, binding := range journal.KeyRoleHistory {
		if binding == status {
			recorded = true
			continue
		}
		if overlaps(binding) {
			return fmt.Errorf("status key shares a key ID or component with journal role %q", binding.Role)
		}
	}
	if !recorded {
		return fmt.Errorf("status key lacks its permanent status role in the journal")
	}
	keys := []HybridPublicKey{bundle.AgentPubKey}
	for _, cert := range bundle.Delegations {
		keys = append(keys, cert.IssuerPubKey, cert.SubjectPubKey)
	}
	for _, key := range keys {
		chainKey, err := keyRoleBindingV2("other", key)
		if err != nil {
			return err
		}
		// No chain key may share an ID or component with any current or
		// retired status binding of any issuer (§6.5 step 2).
		for _, binding := range journal.KeyRoleHistory {
			if binding.Role != "status" {
				continue
			}
			components := []string{binding.Ed25519Digest, binding.MLDSA65Digest}
			if chainKey.KeyID == binding.KeyID || slices.Contains(components, chainKey.Ed25519Digest) || slices.Contains(components, chainKey.MLDSA65Digest) {
				return fmt.Errorf("a proof key shares a key ID or component with a status key")
			}
		}
	}
	if status.KeyID == bundle.VerifierID {
		return fmt.Errorf("status key equals the verifier identity")
	}
	return nil
}
