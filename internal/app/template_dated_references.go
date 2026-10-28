package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// Full fresh input is retained in a bounded source witness, not the 64KiB USER
// confirmation header. Both additions are absent from old originals.
type datedConfirmationSourceV1 struct {
	Protocol    string                 `json:"protocol"`
	PreviewID   funds.ID               `json:"preview_id"`
	BeforeInput planning.ForecastInput `json:"before_input"`
}
type datedConfirmationWitnessV1 struct {
	Protocol          string                           `json:"protocol"`
	SourceWitnessID   funds.ID                         `json:"source_witness_id"`
	SourceWitnessHash string                           `json:"source_witness_hash"`
	Admission         *fundswitness.Boundary           `json:"admission"`
	References        []policy.TemplatePolicyReference `json:"references"`
}

func datedRequiredReferences(compiled policy.CompiledTemplate) ([]funds.ID, error) {
	if compiled.Name != policy.DatedExpenseTemplate {
		return nil, nil
	}
	c, err := compiled.Decode()
	if err != nil {
		return nil, err
	}
	return c.(*policy.DatedExpenseConfig).MustNotReducePolicyIDs, nil
}

func datedProposedInput(before planning.ForecastInput, proposed policy.TemplateVersion) (planning.ForecastInput, error) {
	after, err := planning.CloneForecastInput(before)
	if err != nil {
		return after, err
	}
	versions := []policy.TemplateVersion{}
	for _, v := range after.Versions {
		if v.PolicyID != proposed.PolicyID {
			versions = append(versions, v)
		}
	}
	after.Versions = append(versions, proposed)
	templateSortedVersions(after.Versions)
	return after, nil
}

// Called under the existing environment/USER locks, after original-key lookup
// and source/base checks, before any inventory/authority/adoption writes.
func (s *Service) validateDatedConfirmation(ctx context.Context, tx pgx.Tx, p Principal, preview TemplatePolicyPreview, snapshot templateSnapshot, now time.Time) (*datedConfirmationWitnessV1, error) {
	ids, err := datedRequiredReferences(preview.Compiled)
	if err != nil {
		return nil, reject("INVALID_TEMPLATE_CONFIGURATION", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if !snapshot.SourceWitnessEnabled {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", nil)
	}
	before := snapshot.forecastInput(365)
	proposed := policy.TemplateVersion{PolicyID: preview.PolicyID, VersionID: preview.VersionID, Version: preview.BaseVersion + 1, Scope: preview.Scope, Compiled: preview.Compiled, State: "ACTIVE", ConfirmedAt: now, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: preview.Compiled.Hash}
	after, err := datedProposedInput(before, proposed)
	if err != nil {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", err)
	}
	refs, err := planning.CompareProtectedPolicyReferencesV1(before, after, proposed.PolicyID, ids)
	if err != nil {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", err)
	}
	forecast, err := planning.Forecast365(after)
	if err != nil {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", err)
	}
	facts := after.Facts
	facts.CurrentSafe, facts.CurrentSafeVerified, facts.ProtectedReferences = forecast.CurrentSafe, true, refs
	if _, err = policy.PreviewTemplate(proposed, facts, now, snapshot.Timezone); err != nil {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", err)
	}
	admission, err := fundsAuthorityAdmission(ctx, tx, p)
	if err != nil || admission == nil {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", err)
	}
	id, hash, err := s.saveTemplateSourceWitnessWithDated(ctx, tx, p, snapshot, &datedConfirmationSourceV1{Protocol: "dated-protected-confirmation-source-v1", PreviewID: preview.ID, BeforeInput: before})
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", nil)
	}
	return &datedConfirmationWitnessV1{Protocol: "dated-protected-confirmation-v1", SourceWitnessID: *id, SourceWitnessHash: hash, Admission: admission, References: refs}, nil
}
