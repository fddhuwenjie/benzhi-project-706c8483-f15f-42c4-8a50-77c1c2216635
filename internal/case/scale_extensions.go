package cases

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"museumenv/internal/rules"
	"museumenv/internal/store"
	"strings"
	"time"
)

type RiskHistoryItem struct {
	Evaluation            store.RiskEvaluation `json:"evaluation"`
	LevelDelta            int                  `json:"level_delta"`
	RiskLevelDelta        int                  `json:"risk_level_delta"`
	ScoreDelta            int                  `json:"score_delta"`
	DeadlineDeltaMinutes  int64                `json:"deadline_delta_minutes"`
	ResponseDeadlineDelta int64                `json:"response_deadline_delta_minutes"`
}
type RiskHistoryView struct {
	IncidentID      string            `json:"incident_id"`
	Items           []RiskHistoryItem `json:"items"`
	PeakReadingID   string            `json:"peak_reading_id,omitempty"`
	PeakExplanation string            `json:"peak_explanation,omitempty"`
	PeakPhase       string            `json:"peak_phase,omitempty"`
}

func (s *Service) RiskHistory(id string, from, to time.Time) (RiskHistoryView, error) {
	in, e := s.Get(id)
	if e != nil {
		return RiskHistoryView{}, e
	}
	out := RiskHistoryView{IncidentID: id, PeakReadingID: in.PeakReadingID, PeakExplanation: in.RiskExplanation}
	for _, r := range in.Readings {
		if r.ReadingID == in.PeakReadingID {
			out.PeakPhase = r.Phase
			break
		}
	}
	prev := (*store.RiskEvaluation)(nil)
	for index, v := range in.RiskEvaluations {
		if v.Sequence != index+1 {
			return RiskHistoryView{}, &Error{Code: "EVIDENCE_INTEGRITY_FAILED", Message: "风险评估序列不连续"}
		}
		include := !((!from.IsZero() && v.EvaluatedAt.Before(from)) || (!to.IsZero() && v.EvaluatedAt.After(to)))
		if !include {
			pv := v
			prev = &pv
			continue
		}
		item := RiskHistoryItem{Evaluation: v}
		if prev != nil {
			item.LevelDelta = rules.RiskRank(rules.RiskLevel(v.RiskLevel)) - rules.RiskRank(rules.RiskLevel(prev.RiskLevel))
			item.RiskLevelDelta = item.LevelDelta
			item.ScoreDelta = v.RiskScore - prev.RiskScore
			item.DeadlineDeltaMinutes = int64(v.ResponseDeadline.Sub(prev.ResponseDeadline) / time.Minute)
			item.ResponseDeadlineDelta = item.DeadlineDeltaMinutes
		}
		out.Items = append(out.Items, item)
		pv := v
		prev = &pv
	}
	return out, nil
}

type FollowUpTask struct {
	HypothesisID   string     `json:"hypothesis_id"`
	Conclusion     string     `json:"conclusion"`
	Evidence       string     `json:"evidence,omitempty"`
	DueAt          *time.Time `json:"due_at,omitempty"`
	Status         string     `json:"status"`
	EvidenceGap    bool       `json:"evidence_gap"`
	LastVerifiedBy string     `json:"last_verified_by,omitempty"`
}
type FollowUpView struct {
	IncidentID        string         `json:"incident_id"`
	Tasks             []FollowUpTask `json:"tasks"`
	SubmissionBlocked bool           `json:"submission_blocked"`
	BlockingReasons   []string       `json:"blocking_reasons,omitempty"`
}

func (s *Service) FollowUps(id, conclusion string, now time.Time) (FollowUpView, error) {
	in, e := s.Get(id)
	if e != nil {
		return FollowUpView{}, e
	}
	if now.IsZero() {
		now = s.now()
	}
	out := FollowUpView{IncidentID: id}
	if in.Inspection == nil {
		return out, nil
	}
	for _, h := range in.Inspection.Hypotheses {
		if conclusion != "" && h.CurrentConclusion != conclusion {
			continue
		}
		t := FollowUpTask{HypothesisID: h.HypothesisID, Conclusion: h.CurrentConclusion, Status: h.CurrentConclusion}
		if len(h.Conclusions) > 0 {
			c := h.Conclusions[len(h.Conclusions)-1]
			t.Evidence = c.Evidence
			t.LastVerifiedBy = c.RecordedBy
			if c.PreviousConclusionID != "" && len(h.Conclusions) > 1 && h.Conclusions[len(h.Conclusions)-2].ConclusionID != c.PreviousConclusionID {
				t.EvidenceGap = true
			}
		}
		if in.Inspection.AlternativeReviewAt != nil {
			d := *in.Inspection.AlternativeReviewAt
			t.DueAt = &d
			if h.CurrentConclusion == "pending" {
				if now.After(d) {
					t.Status = "overdue"
				} else {
					t.Status = "due"
				}
			}
		}
		out.Tasks = append(out.Tasks, t)
	}
	for _, t := range out.Tasks {
		if t.Conclusion == "pending" {
			if t.DueAt == nil {
				out.SubmissionBlocked = true
				out.BlockingReasons = append(out.BlockingReasons, "pending 假设缺少复查时间")
			}
			if in.Inspection.AlternativeMonitoring == "" {
				out.SubmissionBlocked = true
				out.BlockingReasons = append(out.BlockingReasons, "缺少替代监测安排")
			}
		}
	}
	return out, nil
}

type PlanPreflightView struct {
	Version                   int              `json:"version"`
	Passed                    bool             `json:"passed"`
	Failures                  []string         `json:"failures,omitempty"`
	Changes                   []PlanDifference `json:"changes,omitempty"`
	SafetyChangeNotesRequired []string         `json:"safety_change_notes_required,omitempty"`
	Summary                   any              `json:"summary,omitempty"`
}

func (s *Service) ContextSnapshot(id string) (map[string]any, error) {
	in, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"incident_id": id, "current_version": in.CurrentContextVersion, "snapshots": in.ContextSnapshots}, nil
}

func (s *Service) ReassessmentTasks(id string, status string, owner string, from, to time.Time) ([]store.ReassessmentTask, error) {
	in, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := []store.ReassessmentTask{}
	for _, task := range in.ReassessmentTasks {
		if status != "" && task.Status != status {
			continue
		}
		if owner != "" && task.OwnerID != owner {
			continue
		}
		if !from.IsZero() && task.DueAt.Before(from) {
			continue
		}
		if !to.IsZero() && task.DueAt.After(to) {
			continue
		}
		task.RemainingMinutes = int64(task.DueAt.Sub(now) / time.Minute)
		if task.Status == "pending" && !task.DueAt.After(now) {
			task.Status = "overdue"
		}
		out = append(out, task)
	}
	return out, nil
}

func (s *Service) PlanPreflight(id string, input SubmitPlanInput) (PlanPreflightView, error) {
	in, e := s.Get(id)
	if e != nil {
		return PlanPreflightView{}, e
	}
	if in.Status == store.StatusSealed {
		return PlanPreflightView{}, precondition("事件已封存，不能预演方案")
	}
	expected := input.Meta.ExpectedRevision
	if expected == 0 {
		expected = input.ExpectedRevision
	}
	if expected != in.Revision {
		return PlanPreflightView{}, &Error{Code: "PRECONDITION_FAILED", Message: "expected_revision 已过期"}
	}
	out := PlanPreflightView{Version: int(in.Revision), Passed: true, Summary: map[string]any{"risk_level": in.RiskLevel, "sensitivity": in.Sensitivity}}
	// Mirror the precondition gates enforced by SubmitPlan so preflight cannot
	// report a plan as submittable when SubmitPlan would reject it for state.
	if input.PreflightVersion != 0 && input.PreflightVersion != int(in.Revision) {
		out.Failures = append(out.Failures, "方案预检版本已过期，必须重新预检")
	}
	if in.Status != store.StatusInspected && !(in.Status == store.StatusPlanSubmitted && in.Plan != nil && in.Plan.ReviewStatus == "rejected") {
		out.Failures = append(out.Failures, "当前状态不允许提交干预方案")
	}
	// Reuse the exact field-level checks that SubmitPlan runs inside its
	// mutation callback, including the empty-steps gate, inspection readiness
	// and resubmission rules.
	out.Failures = append(out.Failures, planSubmissionFailures(in, input)...)
	// Surface detailed safety-envelope change diagnostics for callers that
	// want to pre-populate safety_change_notes; these do not add failures
	// beyond what planSubmissionFailures already reports.
	if in.Plan != nil && in.Plan.SafetyEnvelope != nil && input.SafetyEnvelope != nil {
		old, new := *in.Plan.SafetyEnvelope, *input.SafetyEnvelope
		checks := []struct {
			n    string
			a, b float64
		}{{"max_temperature_change_per_hour", old.MaxTemperatureChangePerHour, new.MaxTemperatureChangePerHour}, {"max_humidity_change_per_hour", old.MaxHumidityChangePerHour, new.MaxHumidityChangePerHour}}
		for _, c := range checks {
			if c.a != c.b {
				out.Changes = append(out.Changes, PlanDifference{Field: c.n, From: c.a, To: c.b})
				if _, ok := input.SafetyChangeNotes[c.n]; !ok {
					out.SafetyChangeNotesRequired = append(out.SafetyChangeNotesRequired, c.n)
				}
			}
		}
	}
	out.Passed = len(out.Failures) == 0
	return out, nil
}

type ExecutionSummary struct {
	IncidentID         string                 `json:"incident_id"`
	ExecutionID        string                 `json:"execution_id,omitempty"`
	Steps              []StepSummary          `json:"steps"`
	CompletionRate     float64                `json:"completion_rate"`
	Materials          []MaterialBatchSummary `json:"materials"`
	Deviations         map[string]int         `json:"deviations"`
	ObservationBlocked bool                   `json:"observation_blocked"`
	BlockingReasons    []string               `json:"blocking_reasons,omitempty"`
}

func (s *Service) MaterialBatchTracking(batch string) ([]MaterialBatchSummary, error) {
	items, err := s.repository.List()
	if err != nil {
		return nil, err
	}
	result := []MaterialBatchSummary{}
	for _, incident := range items {
		for _, execution := range incident.Executions {
			for _, material := range execution.Materials {
				if batch == "" || strings.EqualFold(strings.TrimSpace(material.BatchNumber), strings.TrimSpace(batch)) {
					result = append(result, MaterialBatchSummary{BatchNumber: material.BatchNumber, Name: material.Name, LatestExpiresAt: material.ExpiresAt, Operators: []string{execution.OperatorID}, QuantityValues: []any{material.Quantity}, UseCount: 1})
				}
			}
		}
	}
	return result, nil
}

type StepSummary struct {
	StepNumber      int    `json:"step_number"`
	Step            string `json:"step"`
	Status          string `json:"status"`
	DeviationReason string `json:"deviation_reason,omitempty"`
}

func (s *Service) ExecutionSummary(id, executionID string) (ExecutionSummary, error) {
	in, e := s.Get(id)
	if e != nil {
		return ExecutionSummary{}, e
	}
	out := ExecutionSummary{IncidentID: id, ExecutionID: executionID, Deviations: map[string]int{}}
	exes := in.Executions
	if executionID != "" {
		exes = nil
		for _, x := range in.Executions {
			if x.ExecutionID == executionID {
				exes = append(exes, x)
			}
		}
	}
	total, done := 0, 0
	for _, x := range exes {
		for _, r := range x.StepResults {
			total++
			st := r.Result
			if st == "completed" {
				done++
			}
			out.Steps = append(out.Steps, StepSummary{r.StepNumber, r.Step, st, r.DeviationReason})
			if r.DeviationReason != "" {
				out.Deviations["pending"]++
			}
		}
		for _, d := range x.Deviations {
			out.Deviations[d.CurrentDecision]++
		}
	}
	if total > 0 {
		out.CompletionRate = float64(done) / float64(total)
	}
	out.Materials, _ = s.MaterialTracking(id, 7)
	for k := range out.Deviations {
		if k == "pending" || k == "returned" {
			out.ObservationBlocked = true
			out.BlockingReasons = append(out.BlockingReasons, fmt.Sprintf("存在 %s 偏差", k))
		}
	}
	return out, nil
}

type ReopenPreview struct {
	IncidentID        string                `json:"incident_id"`
	Revision          int64                 `json:"revision"`
	Ready             bool                  `json:"ready"`
	Sealed            bool                  `json:"sealed"`
	Checks            []rules.ReadinessItem `json:"checks"`
	ManifestDigest    string                `json:"manifest_digest"`
	Stale             bool                  `json:"stale"`
	RiskLevel         string                `json:"risk_level"`
	ObservationWindow int                   `json:"observation_window"`
	AuditTailDigest   string                `json:"audit_tail_digest,omitempty"`
	CheckedAt         time.Time             `json:"checked_at"`
}

func (s *Service) ReopenPreview(id, role string, revision int64) (ReopenPreview, error) {
	in, e := s.Get(id)
	if e != nil {
		return ReopenPreview{}, e
	}
	checkedAt := s.now()
	p := ReopenPreview{IncidentID: id, Revision: in.Revision, Sealed: in.Status == store.StatusSealed, Stale: revision > 0 && revision != in.Revision, RiskLevel: in.RiskLevel, ObservationWindow: in.CurrentObservationWindow, CheckedAt: checkedAt}
	r := readinessFor(in, role == "duty_supervisor", checkedAt)
	p.Ready = r.Ready
	p.Checks = r.Checks
	b, _ := json.Marshal(struct {
		I *store.EnvironmentIncident
		C []rules.ReadinessItem
	}{in, r.Checks})
	h := sha256.Sum256(b)
	p.ManifestDigest = hex.EncodeToString(h[:])
	if events, err := s.repository.Timeline(id); err == nil && len(events) > 0 {
		p.AuditTailDigest = events[len(events)-1].EventDigest
	}
	return p, nil
}

type ExpireInput struct {
	Meta CommandMeta `json:"meta"`
}
type RenewInput struct {
	Meta            CommandMeta `json:"meta"`
	OwnerID         string      `json:"owner_id"`
	NextAction      string      `json:"next_action"`
	CommitmentDueAt time.Time   `json:"commitment_due_at"`
}

func (s *Service) ExpireCommitment(id, cid string, in ExpireInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(in.Meta, true); err != nil {
		return nil, false, err
	}
	now := s.now()
	return s.update(id, in.Meta, "expire_deadline_commitment", "deadline.commitment_expired", in, func(x *store.EnvironmentIncident) error {
		for i := range x.DeadlineCommitments {
			c := &x.DeadlineCommitments[i]
			if c.CommitmentID == cid {
				if c.CompletedAt != nil || c.InvalidatedAt != nil {
					return precondition("承诺已结束")
				}
				if c.CommitmentDueAt.After(now) {
					return precondition("承诺尚未到期")
				}
				c.InvalidatedAt = &now
				c.Status = "expired"
				c.OwnerID = ""
				x.CommitmentOwnerID = ""
				return nil
			}
		}
		return invalid("commitment_id 不存在")
	})
}
func (s *Service) RenewCommitment(id, cid string, in RenewInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(in.Meta, true); err != nil {
		return nil, false, err
	}
	if in.Meta.ActorRole != "duty_supervisor" {
		return nil, false, precondition("仅值班主管可以续期承诺")
	}
	if strings.TrimSpace(in.OwnerID) == "" || strings.TrimSpace(in.NextAction) == "" || in.CommitmentDueAt.IsZero() {
		return nil, false, invalid("owner_id、next_action 和 commitment_due_at 不能为空")
	}
	now := s.now()
	return s.update(id, in.Meta, "renew_deadline_commitment", "deadline.commitment_renewed", in, func(x *store.EnvironmentIncident) error {
		for i := range x.DeadlineCommitments {
			c := &x.DeadlineCommitments[i]
			if c.CommitmentID == cid {
				if c.Status != "expired" {
					return precondition("仅 expired 承诺可以续期")
				}
				if !in.CommitmentDueAt.After(now) || in.CommitmentDueAt.After(now.Add(rules.MaximumRemedyWindow(rules.RiskLevel(x.RiskLevel)))) {
					return invalid("新的承诺期限超出允许补救窗口")
				}
				c.Status = "effective"
				c.InvalidatedAt = nil
				c.OwnerID = normalizeBusinessID(in.OwnerID)
				c.NextAction = strings.TrimSpace(in.NextAction)
				c.CommitmentDueAt = in.CommitmentDueAt.UTC()
				c.CommittedAt = now
				x.CommitmentOwnerID = c.OwnerID
				return nil
			}
		}
		return invalid("commitment_id 不存在")
	})
}
