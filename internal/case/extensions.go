package cases

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"museumenv/internal/rules"
	"museumenv/internal/store"
)

type HypothesisInput struct {
	HypothesisID       string `json:"hypothesis_id,omitempty"`
	Description        string `json:"description"`
	VerificationMethod string `json:"verification_method,omitempty"`
	Evidence           string `json:"evidence,omitempty"`
	Conclusion         string `json:"conclusion,omitempty"`
}

type HypothesisInputs []HypothesisInput

func (values *HypothesisInputs) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	result := make(HypothesisInputs, 0, len(raw))
	for _, item := range raw {
		var text string
		if err := json.Unmarshal(item, &text); err == nil {
			result = append(result, HypothesisInput{Description: text})
			continue
		}
		var structured HypothesisInput
		if err := json.Unmarshal(item, &structured); err != nil {
			return fmt.Errorf("cause_hypotheses 必须为字符串或结构化假设: %w", err)
		}
		result = append(result, structured)
	}
	*values = result
	return nil
}

type DeviationInput struct {
	Type             string `json:"type"`
	Reason           string `json:"reason"`
	ImmediateControl string `json:"immediate_control"`
	PlanStepNumber   int    `json:"plan_step_number"`
}

func toRuleSafety(value store.SafetyEnvelope) rules.SafetyEnvelopeInput {
	return rules.SafetyEnvelopeInput{MaxTemperatureChangePerHour: value.MaxTemperatureChangePerHour, MaxHumidityChangePerHour: value.MaxHumidityChangePerHour, MaxExposureMinutes: value.MaxExposureMinutes, StopTemperature: toRuleRange(value.StopTemperature), StopHumidity: toRuleRange(value.StopHumidity), RollbackSteps: value.RollbackSteps, RollbackOwnerID: value.RollbackOwnerID}
}

type AcknowledgeDeadlineInput struct {
	Meta            CommandMeta `json:"meta"`
	Reason          string      `json:"reason"`
	OwnerID         string      `json:"owner_id"`
	NextAction      string      `json:"next_action"`
	CommitmentDueAt time.Time   `json:"commitment_due_at"`
}

func activeDeadlineCommitment(incident *store.EnvironmentIncident, now time.Time) *store.DeadlineCommitment {
	for i := len(incident.DeadlineCommitments) - 1; i >= 0; i-- {
		item := &incident.DeadlineCommitments[i]
		if item.InvalidatedAt == nil && item.CompletedAt == nil && item.CommitmentDueAt.After(now) {
			return item
		}
	}
	return nil
}

func (s *Service) AcknowledgeDeadline(incidentID string, input AcknowledgeDeadlineInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Meta.ActorRole != "duty_supervisor" {
		return nil, false, precondition("仅值班主管可以确认处置时限升级")
	}
	if err := requireFields(map[string]string{"reason": input.Reason, "owner_id": input.OwnerID, "next_action": input.NextAction}); err != nil {
		return nil, false, err
	}
	now := s.now()
	if !input.CommitmentDueAt.After(now) {
		return nil, false, invalid("commitment_due_at 必须晚于确认时刻")
	}
	return s.update(incidentID, input.Meta, "acknowledge_deadline", "deadline.acknowledged", input, func(incident *store.EnvironmentIncident) error {
		assessment := rules.AssessEscalation(incident.ResponseDeadline, now, incident.Status == store.StatusSealed, activeDeadlineCommitment(incident, now) != nil)
		if assessment.Status != "due_soon" && assessment.Status != "overdue_unacknowledged" {
			return precondition("仅即将到期或逾期未确认事件可以登记承诺")
		}
		if input.CommitmentDueAt.After(now.Add(rules.MaximumRemedyWindow(rules.RiskLevel(incident.RiskLevel)))) {
			return invalid(fmt.Sprintf("承诺完成时间超过风险 %s 的最大补救窗口", incident.RiskLevel))
		}
		if activeDeadlineCommitment(incident, now) != nil {
			return precondition("当前逾期阶段已有有效承诺")
		}
		incident.DeadlineCommitments = append(incident.DeadlineCommitments, store.DeadlineCommitment{CommitmentID: s.id("commitment"), Stage: assessment.Status, Reason: strings.TrimSpace(input.Reason), OwnerID: normalizeBusinessID(input.OwnerID), NextAction: strings.TrimSpace(input.NextAction), CommittedAt: now, CommitmentDueAt: input.CommitmentDueAt.UTC(), ConfirmedBy: input.Meta.ActorID, Status: "effective"})
		updated := rules.AssessEscalation(incident.ResponseDeadline, now, false, true)
		incident.EscalationStatus, incident.RemainingMinutes, incident.CommitmentOwnerID = store.EscalationStatus(updated.Status), updated.RemainingMinutes, normalizeBusinessID(input.OwnerID)
		return nil
	})
}

type CompleteCommitmentInput struct {
	Meta CommandMeta `json:"meta"`
	Note string      `json:"note"`
}

func (s *Service) CompleteDeadlineCommitment(incidentID, commitmentID string, input CompleteCommitmentInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "complete_deadline_commitment", "deadline.commitment_completed", input, func(incident *store.EnvironmentIncident) error {
		for i := range incident.DeadlineCommitments {
			item := &incident.DeadlineCommitments[i]
			if item.CommitmentID == commitmentID {
				if item.CompletedAt != nil || item.InvalidatedAt != nil {
					return precondition("承诺已完成或失效")
				}
				item.CompletedAt = &now
				item.Status = "completed"
				updated := rules.AssessEscalation(incident.ResponseDeadline, now, incident.Status == store.StatusSealed, false)
				incident.EscalationStatus, incident.RemainingMinutes, incident.CommitmentOwnerID = store.EscalationStatus(updated.Status), updated.RemainingMinutes, ""
				return nil
			}
		}
		return invalid("commitment_id 不存在")
	})
}

type ValidateHypothesisInput struct {
	Meta                 CommandMeta `json:"meta"`
	Conclusion           string      `json:"conclusion"`
	VerificationMethod   string      `json:"verification_method"`
	Evidence             string      `json:"evidence"`
	PreviousConclusionID string      `json:"previous_conclusion_id,omitempty"`
}

func (s *Service) ValidateHypothesis(incidentID, hypothesisID string, input ValidateHypothesisInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Conclusion != "pending" && input.Conclusion != "supported" && input.Conclusion != "excluded" && input.Conclusion != "confirmed" {
		return nil, false, invalid("conclusion 必须为 pending、supported、excluded 或 confirmed")
	}
	if err := requireFields(map[string]string{"verification_method": input.VerificationMethod, "evidence": input.Evidence}); err != nil {
		return nil, false, err
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "validate_hypothesis", "inspection.hypothesis_validated", input, func(incident *store.EnvironmentIncident) error {
		if incident.Status == store.StatusReported || incident.Status == store.StatusSealed || incident.Inspection == nil {
			return precondition("仅已完成现场复核且未封存事件可以追加假设结论")
		}
		for i := range incident.Inspection.Hypotheses {
			hypothesis := &incident.Inspection.Hypotheses[i]
			if hypothesis.HypothesisID != hypothesisID {
				continue
			}
			if input.Conclusion == "confirmed" || input.Conclusion == "supported" {
				for _, other := range incident.Inspection.Hypotheses {
					if other.HypothesisID != hypothesisID && (other.CurrentConclusion == "confirmed" || other.CurrentConclusion == "supported") {
						return &Error{Code: "CAUSE_HYPOTHESIS_CONFLICT", Message: "互斥假设不能同时确认"}
					}
				}
			}
			previousID := ""
			if len(hypothesis.Conclusions) > 0 {
				previousID = hypothesis.Conclusions[len(hypothesis.Conclusions)-1].ConclusionID
			}
			if hypothesis.CurrentConclusion != input.Conclusion && previousID != input.PreviousConclusionID {
				return precondition("结论变化必须引用上一条 previous_conclusion_id")
			}
			conclusion := store.CauseConclusion{ConclusionID: s.id("conclusion"), HypothesisID: hypothesisID, Conclusion: input.Conclusion, VerificationMethod: strings.TrimSpace(input.VerificationMethod), Evidence: strings.TrimSpace(input.Evidence), PreviousConclusionID: previousID, RecordedBy: input.Meta.ActorID, RecordedAt: now}
			hypothesis.Conclusions = append(hypothesis.Conclusions, conclusion)
			hypothesis.CurrentConclusion = input.Conclusion
			return nil
		}
		return invalid("hypothesis_id 不存在")
	})
}

type SensorHandoverInput struct {
	Meta                 CommandMeta    `json:"meta"`
	NewSensorID          string         `json:"new_sensor_id"`
	RemovedAt            time.Time      `json:"removed_at"`
	InstalledAt          time.Time      `json:"installed_at"`
	HandedOverBy         string         `json:"handed_over_by"`
	Reason               string         `json:"reason"`
	CalibrationReference string         `json:"calibration_reference"`
	OldSensorReadings    []ReadingInput `json:"old_sensor_readings"`
	NewSensorReadings    []ReadingInput `json:"new_sensor_readings"`
}

func (s *Service) HandoverSensor(incidentID string, input SensorHandoverInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if err := requireFields(map[string]string{"new_sensor_id": input.NewSensorID, "handed_over_by": input.HandedOverBy, "reason": input.Reason, "calibration_reference": input.CalibrationReference}); err != nil {
		return nil, false, err
	}
	if input.RemovedAt.IsZero() || input.InstalledAt.IsZero() || input.InstalledAt.Before(input.RemovedAt) {
		return nil, false, invalid("拆装时间不能为空且 installed_at 不得早于 removed_at")
	}
	if len(input.OldSensorReadings) == 0 || len(input.OldSensorReadings) > 50 || len(input.OldSensorReadings) != len(input.NewSensorReadings) {
		return nil, false, invalid("新旧传感器必须提交 1 至 50 组重叠读数")
	}
	oldRule := make([]rules.DiscoveryReading, len(input.OldSensorReadings))
	newRule := make([]rules.DiscoveryReading, len(input.NewSensorReadings))
	for i := range input.OldSensorReadings {
		if input.OldSensorReadings[i].CapturedAt.IsZero() || input.NewSensorReadings[i].CapturedAt.IsZero() || input.OldSensorReadings[i].CapturedAt.Before(input.RemovedAt) || input.OldSensorReadings[i].CapturedAt.After(input.InstalledAt) {
			return nil, false, invalid(fmt.Sprintf("第 %d 组重叠读数必须在拆装时段内采集", i+1))
		}
		if input.OldSensorReadings[i].SensorStatus != "ok" || input.NewSensorReadings[i].SensorStatus != "ok" {
			return nil, false, invalid("重叠校准读数 sensor_status 必须为 ok")
		}
		if err := validatePhysicalReading(input.OldSensorReadings[i]); err != nil {
			return nil, false, err
		}
		if err := validatePhysicalReading(input.NewSensorReadings[i]); err != nil {
			return nil, false, err
		}
		oldRule[i] = rules.DiscoveryReading{CapturedAt: input.OldSensorReadings[i].CapturedAt, Temperature: input.OldSensorReadings[i].TemperatureCelsius, Humidity: input.OldSensorReadings[i].RelativeHumidityPercent}
		newRule[i] = rules.DiscoveryReading{CapturedAt: input.NewSensorReadings[i].CapturedAt, Temperature: input.NewSensorReadings[i].TemperatureCelsius, Humidity: input.NewSensorReadings[i].RelativeHumidityPercent}
	}
	if failures := rules.ValidateSensorOverlap(oldRule, newRule, input.CalibrationReference); len(failures) > 0 {
		return nil, false, invalid(strings.Join(failures, "；"))
	}
	input.NewSensorID = normalizeBusinessID(input.NewSensorID)
	now := s.now()
	return s.update(incidentID, input.Meta, "handover_sensor", "sensor.handed_over", input, func(incident *store.EnvironmentIncident) error {
		if incident.Status == store.StatusSealed || incident.Inspection == nil || incident.Inspection.SensorTrustworthy {
			return precondition("仅现场复核判定原传感器不可信后允许交接")
		}
		if input.NewSensorID == incident.SensorID {
			return invalid("新传感器不能与当前传感器相同")
		}
		oldReadings := make([]store.EnvironmentReading, len(input.OldSensorReadings))
		newReadings := make([]store.EnvironmentReading, len(input.NewSensorReadings))
		for i := range input.OldSensorReadings {
			oldReadings[i] = s.makeReading(incidentID, input.Meta.ActorID, "sensor_handover_old", input.OldSensorReadings[i])
			oldReadings[i].SensorID = incident.SensorID
			oldReadings[i].CalibrationReference = input.CalibrationReference
			newReadings[i] = s.makeReading(incidentID, input.Meta.ActorID, "sensor_handover_new", input.NewSensorReadings[i])
			newReadings[i].SensorID = input.NewSensorID
			newReadings[i].CalibrationReference = input.CalibrationReference
		}
		handover := store.SensorHandover{HandoverID: s.id("handover"), OldSensorID: incident.SensorID, NewSensorID: input.NewSensorID, RemovedAt: input.RemovedAt.UTC(), InstalledAt: input.InstalledAt.UTC(), HandedOverBy: strings.TrimSpace(input.HandedOverBy), Reason: strings.TrimSpace(input.Reason), Reference: strings.TrimSpace(input.CalibrationReference), OldReadings: oldReadings, NewReadings: newReadings, CompletedAt: now}
		incident.Readings = append(incident.Readings, oldReadings...)
		incident.Readings = append(incident.Readings, newReadings...)
		incident.SensorHandovers = append(incident.SensorHandovers, handover)
		incident.CurrentContextVersion++
		incident.ContextSnapshots = append(incident.ContextSnapshots, store.ContextSnapshot{Version: incident.CurrentContextVersion, DisplayCaseID: incident.DisplayCaseID, ArtifactID: incident.ArtifactID, SensorID: input.NewSensorID, CalibrationReference: input.CalibrationReference, Validated: true, ValidationResult: "validated_after_handover", OriginalIncidentID: incident.IncidentID, ChangeReason: input.Reason, CreatedAt: now})
		for _, reading := range incident.Readings {
			if reading.Phase == "recovery" && reading.ObservationWindow == incident.CurrentObservationWindow {
				incident.CurrentObservationWindow++
				incident.RecoveryProgress = nil
				incident.LatestObservationInterruption = "传感器交接已结束原观察窗口"
				interruptedAt := now
				incident.LatestObservationInterruptedAt = &interruptedAt
				break
			}
		}
		incident.SensorID = input.NewSensorID
		return nil
	})
}

type ReviewDeviationInput struct {
	Meta            CommandMeta `json:"meta"`
	Decision        string      `json:"decision"`
	RiskExplanation string      `json:"risk_explanation"`
}

func (s *Service) ReviewDeviation(incidentID, executionID, deviationID string, input ReviewDeviationInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Meta.ActorRole != "conservation_engineer" {
		return nil, false, precondition("仅保护工程师可以复核执行偏差")
	}
	if input.Decision != "approve_observation" && input.Decision != "return_execution" {
		return nil, false, invalid("decision 必须为 approve_observation 或 return_execution")
	}
	if strings.TrimSpace(input.RiskExplanation) == "" {
		return nil, false, invalid("risk_explanation 不能为空")
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "review_deviation", "execution.deviation_reviewed", input, func(incident *store.EnvironmentIncident) error {
		for executionIndex := range incident.Executions {
			execution := &incident.Executions[executionIndex]
			if execution.ExecutionID != executionID {
				continue
			}
			if execution.OperatorID == input.Meta.ActorID {
				return precondition("执行人不得审核自己的偏差")
			}
			for deviationIndex := range execution.Deviations {
				deviation := &execution.Deviations[deviationIndex]
				if deviation.DeviationID != deviationID {
					continue
				}
				if deviation.CurrentDecision != "pending" {
					return precondition("该偏差已经复核")
				}
				decision := "approved"
				if input.Decision == "return_execution" {
					decision = "returned"
				}
				deviation.Reviews = append(deviation.Reviews, store.DeviationReview{ReviewID: s.id("deviation-review"), Decision: decision, RiskExplanation: strings.TrimSpace(input.RiskExplanation), ReviewerID: input.Meta.ActorID, ReviewedAt: now})
				deviation.CurrentDecision = decision
				execution.DeviationGate = deviationGate(execution.Deviations)
				if incident.Execution != nil && incident.Execution.ExecutionID == execution.ExecutionID {
					incident.Execution = execution
				}
				return nil
			}
			return invalid("deviation_id 不存在")
		}
		return invalid("execution_id 不存在")
	})
}

func deviationGate(items []store.ExecutionDeviation) string {
	for _, item := range items {
		if item.CurrentDecision == "returned" {
			return "returned"
		}
		if item.CurrentDecision == "pending" {
			return "pending_review"
		}
	}
	return "clear"
}

func recoveryPolicyVersion(incident *store.EnvironmentIncident) string {
	planVersion := 0
	if incident.Plan != nil {
		planVersion = incident.Plan.Version
	}
	return fmt.Sprintf("recovery-v1-%s-%s-plan-%d-window-%d", incident.RiskLevel, incident.Sensitivity, planVersion, incident.CurrentObservationWindow)
}

type RecoveryProgressView struct {
	Policy                 store.RecoveryPolicySnapshot `json:"policy"`
	Progress               rules.RecoveryProgress       `json:"progress"`
	Segments               []ObservationSegmentView     `json:"segments,omitempty"`
	Interruptions          []ObservationInterruption    `json:"interruptions,omitempty"`
	NextSampleDueAt        *time.Time                   `json:"next_sample_due_at,omitempty"`
	SamplingStatus         string                       `json:"sampling_status"`
	StableMinutes          int64                        `json:"stable_minutes"`
	ValidReadings          int                          `json:"valid_readings"`
	RemainingReadings      int                          `json:"remaining_readings"`
	EarliestVerificationAt *time.Time                   `json:"earliest_verification_at,omitempty"`
}

type ObservationSegmentView struct {
	Window          int     `json:"window"`
	Segment         int     `json:"segment"`
	ValidReadings   int     `json:"valid_readings"`
	StableMinutes   int64   `json:"stable_minutes"`
	MaxGapMinutes   int64   `json:"max_gap_minutes"`
	TemperatureMean float64 `json:"temperature_mean"`
	HumidityMean    float64 `json:"humidity_mean"`
	TemperaturePeak float64 `json:"temperature_peak"`
	HumidityPeak    float64 `json:"humidity_peak"`
}
type ObservationInterruption struct {
	Window     int        `json:"window"`
	Segment    int        `json:"segment"`
	Reason     string     `json:"reason"`
	At         time.Time  `json:"at"`
	PreviousAt *time.Time `json:"previous_at,omitempty"`
}

type InspectionReport struct {
	IncidentID                   string                     `json:"incident_id"`
	SensorID                     string                     `json:"sensor_id"`
	IndependentReading           store.EnvironmentReading   `json:"independent_reading"`
	TemperatureDifference        float64                    `json:"temperature_difference"`
	HumidityDifference           float64                    `json:"humidity_difference"`
	MedianTemperatureDifference  float64                    `json:"median_temperature_difference,omitempty"`
	MedianHumidityDifference     float64                    `json:"median_humidity_difference,omitempty"`
	MaximumTemperatureDifference float64                    `json:"maximum_temperature_difference,omitempty"`
	MaximumHumidityDifference    float64                    `json:"maximum_humidity_difference,omitempty"`
	IndependentReadings          []store.EnvironmentReading `json:"independent_readings,omitempty"`
	Conclusion                   string                     `json:"conclusion"`
	IsolationReason              string                     `json:"isolation_reason,omitempty"`
	Handover                     *store.SensorHandover      `json:"sensor_handover,omitempty"`
	Coverage                     struct {
		BeforeStart *time.Time `json:"before_start,omitempty"`
		BeforeEnd   *time.Time `json:"before_end,omitempty"`
		AfterStart  *time.Time `json:"after_start,omitempty"`
		AfterEnd    *time.Time `json:"after_end,omitempty"`
	} `json:"coverage"`
	Failures           []string `json:"failures,omitempty"`
	EvidenceAdmissible bool     `json:"evidence_admissible"`
	SubmissionBlocked  bool     `json:"submission_blocked"`
	MissingReadings    []string `json:"missing_readings,omitempty"`
	HypothesesToReview []string `json:"hypotheses_to_review,omitempty"`
	IsolationGaps      []string `json:"isolation_gaps,omitempty"`
}

func (s *Service) InspectionReport(incidentID string) (InspectionReport, error) {
	incident, err := s.Get(incidentID)
	if err != nil {
		return InspectionReport{}, err
	}
	if incident.Inspection == nil {
		return InspectionReport{}, precondition("尚未完成现场复核")
	}
	r := InspectionReport{IncidentID: incidentID, SensorID: incident.SensorID, IndependentReading: incident.Inspection.IndependentReading, IndependentReadings: incident.Inspection.IndependentReadings, TemperatureDifference: incident.Inspection.TemperatureDifference, HumidityDifference: incident.Inspection.HumidityDifference, MedianTemperatureDifference: incident.Inspection.MedianTemperatureDifference, MedianHumidityDifference: incident.Inspection.MedianHumidityDifference, MaximumTemperatureDifference: incident.Inspection.MaximumTemperatureDifference, MaximumHumidityDifference: incident.Inspection.MaximumHumidityDifference, Conclusion: incident.Inspection.ReportConclusion, EvidenceAdmissible: incident.Inspection.SensorTrustworthy}
	if r.Conclusion == "" {
		r.Conclusion = "trustworthy"
	}
	if !incident.Inspection.SensorTrustworthy {
		r.Conclusion = "untrustworthy"
		r.IsolationReason = incident.Inspection.IsolationMeasure
		if r.IsolationReason == "" {
			r.IsolationReason = incident.Inspection.AlternativeMonitoring
		}
	}
	if len(incident.SensorHandovers) > 0 {
		h := incident.SensorHandovers[len(incident.SensorHandovers)-1]
		r.Handover = &h
		if len(h.OldReadings) > 0 {
			a, b := h.OldReadings[0].CapturedAt, h.OldReadings[len(h.OldReadings)-1].CapturedAt
			r.Coverage.BeforeStart = &a
			r.Coverage.BeforeEnd = &b
		}
		if len(h.NewReadings) > 0 {
			a, b := h.NewReadings[0].CapturedAt, h.NewReadings[len(h.NewReadings)-1].CapturedAt
			r.Coverage.AfterStart = &a
			r.Coverage.AfterEnd = &b
		}
	}
	if !incident.Inspection.SensorTrustworthy && r.Handover == nil {
		r.Failures = append(r.Failures, "原传感器不可信但缺少交接记录")
		r.MissingReadings = append(r.MissingReadings, "可信传感器独立复测读数")
	}
	for _, hypothesis := range incident.Inspection.Hypotheses {
		if hypothesis.CurrentConclusion == "pending" {
			r.HypothesesToReview = append(r.HypothesesToReview, hypothesis.HypothesisID)
		}
	}
	if strings.TrimSpace(incident.Inspection.IsolationMeasure) == "" {
		r.IsolationGaps = append(r.IsolationGaps, "临时隔离措施")
	}
	for _, reading := range incident.Readings {
		if reading.Phase == "recovery" && len(incident.SensorHandovers) > 0 && reading.CapturedAt.After(incident.SensorHandovers[len(incident.SensorHandovers)-1].InstalledAt) && reading.SensorID == incident.SensorHandovers[len(incident.SensorHandovers)-1].OldSensorID {
			r.Failures = append(r.Failures, "交接后观察数据仍引用旧传感器")
		}
	}
	r.SubmissionBlocked = len(r.Failures) > 0 || len(r.MissingReadings) > 0 || len(r.IsolationGaps) > 0 || (len(r.HypothesesToReview) > 0 && strings.TrimSpace(incident.Inspection.AlternativeMonitoring) == "")
	return r, nil
}

type PlanDifference struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}
type PlanDiffView struct {
	IncidentID  string           `json:"incident_id"`
	FromVersion int              `json:"from_version"`
	ToVersion   int              `json:"to_version"`
	Differences []PlanDifference `json:"differences"`
}

func (s *Service) PlanDiff(incidentID string, fromVersion, toVersion int) (PlanDiffView, error) {
	incident, err := s.Get(incidentID)
	if err != nil {
		return PlanDiffView{}, err
	}
	if fromVersion < 1 || toVersion < 1 || fromVersion == toVersion {
		return PlanDiffView{}, invalid("方案版本游标无效")
	}
	var from, to *store.InterventionPlan
	for i := range incident.PlanVersions {
		if incident.PlanVersions[i].Version == fromVersion {
			p := incident.PlanVersions[i]
			from = &p
		}
		if incident.PlanVersions[i].Version == toVersion {
			p := incident.PlanVersions[i]
			to = &p
		}
	}
	if from == nil || to == nil {
		return PlanDiffView{}, invalid("方案版本不存在或不属于当前事件")
	}
	view := PlanDiffView{IncidentID: incidentID, FromVersion: fromVersion, ToVersion: toVersion}
	add := func(field string, a, b any) {
		if fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) {
			view.Differences = append(view.Differences, PlanDifference{Field: field, From: a, To: b})
		}
	}
	add("steps", from.Steps, to.Steps)
	add("target_temperature_range", from.TargetTemperatureRange, to.TargetTemperatureRange)
	add("target_humidity_range", from.TargetHumidityRange, to.TargetHumidityRange)
	add("isolation_required", from.IsolationRequired, to.IsolationRequired)
	add("correction_resolutions", from.CorrectionResolutions, to.CorrectionResolutions)
	add("safety_envelope", from.SafetyEnvelope, to.SafetyEnvelope)
	add("safety_change_notes", from.SafetyChangeNotes, to.SafetyChangeNotes)
	return view, nil
}

type MaterialBatchSummary struct {
	Name                   string    `json:"name"`
	BatchNumber            string    `json:"batch_number"`
	UseCount               int       `json:"use_count"`
	TotalQuantity          float64   `json:"total_quantity"`
	QuantityValues         []any     `json:"quantity_values,omitempty"`
	LatestExpiresAt        time.Time `json:"latest_expires_at"`
	Expiring               bool      `json:"expiring"`
	ExecutionIDs           []string  `json:"execution_ids"`
	PlanVersions           []int     `json:"plan_versions"`
	Operators              []string  `json:"operators"`
	DuplicateReuseConflict bool      `json:"duplicate_reuse_conflict"`
	DaysUntilExpiry        int64     `json:"days_until_expiry"`
}

type materialTrackingCacheEntry struct {
	incidentID string
	revision   int64
	items      []MaterialBatchSummary
}

func (s *Service) MaterialTracking(incidentID string, warningDays int) ([]MaterialBatchSummary, error) {
	incident, err := s.Get(incidentID)
	if err != nil {
		return nil, err
	}
	if warningDays <= 0 || warningDays > 365 {
		return nil, invalid("warning_days 必须在 1 至 365 之间")
	}
	s.materialTrackingMu.Lock()
	if s.materialTrackingCache.incidentID == incidentID && s.materialTrackingCache.revision == incident.Revision {
		items := s.materialTrackingCache.items
		s.materialTrackingMu.Unlock()
		return items, nil
	}
	s.materialTrackingMu.Unlock()
	now := s.now()
	by := map[string]*MaterialBatchSummary{}
	for _, execution := range incident.Executions {
		for _, m := range execution.Materials {
			name := strings.ToLower(strings.TrimSpace(m.Name))
			batch := strings.ToLower(strings.TrimSpace(m.BatchNumber))
			if name == "" || batch == "" {
				continue
			}
			key := name + "\x00" + batch
			item := by[key]
			if item == nil {
				item = &MaterialBatchSummary{Name: strings.TrimSpace(m.Name), BatchNumber: strings.TrimSpace(m.BatchNumber), LatestExpiresAt: m.ExpiresAt}
				by[key] = item
			}
			item.UseCount++
			item.QuantityValues = append(item.QuantityValues, m.Quantity)
			item.ExecutionIDs = append(item.ExecutionIDs, execution.ExecutionID)
			item.PlanVersions = append(item.PlanVersions, execution.PlanVersion)
			item.Operators = append(item.Operators, execution.OperatorID)
			if m.ExpiresAt.After(item.LatestExpiresAt) {
				item.LatestExpiresAt = m.ExpiresAt
			}
			_ = now
		}
	}
	result := make([]MaterialBatchSummary, 0, len(by))
	for _, item := range by {
		item.Expiring = !item.LatestExpiresAt.IsZero() && !item.LatestExpiresAt.After(now.Add(time.Duration(warningDays)*24*time.Hour))
		if !item.LatestExpiresAt.IsZero() {
			item.DaysUntilExpiry = int64(item.LatestExpiresAt.Sub(now).Hours() / 24)
		}
		item.DuplicateReuseConflict = item.UseCount > 1
		for _, q := range item.QuantityValues {
			switch v := q.(type) {
			case float64:
				item.TotalQuantity += v
			case int:
				item.TotalQuantity += float64(v)
			case string:
				if v, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					item.TotalQuantity += v
				}
			}
		}
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].BatchNumber < result[j].BatchNumber })
	s.materialTrackingMu.Lock()
	s.materialTrackingCache = materialTrackingCacheEntry{incidentID: incidentID, revision: incident.Revision, items: result}
	s.materialTrackingMu.Unlock()
	return result, nil
}

func recoveryReadings(incident *store.EnvironmentIncident) []rules.RecoveryReading {
	result := make([]rules.RecoveryReading, 0)
	for _, reading := range incident.Readings {
		if reading.Phase == "recovery" && reading.ObservationWindow == incident.CurrentObservationWindow {
			result = append(result, rules.RecoveryReading{CapturedAt: reading.CapturedAt, Temperature: reading.TemperatureCelsius, Humidity: reading.RelativeHumidityPercent, SensorOK: reading.SensorStatus == "ok" && reading.SensorID == incident.SensorID})
		}
	}
	return result
}

func (s *Service) RecoveryProgress(incidentID string) (RecoveryProgressView, error) {
	return s.RecoveryProgressAt(incidentID, time.Time{})
}

func (s *Service) RecoveryProgressAt(incidentID string, at time.Time) (RecoveryProgressView, error) {
	incident, err := s.Get(incidentID)
	if err != nil {
		return RecoveryProgressView{}, err
	}
	if incident.Plan == nil {
		return RecoveryProgressView{}, precondition("缺少已批准干预方案")
	}
	policy := rules.PolicyFor(rules.RiskLevel(incident.RiskLevel), rules.Sensitivity(incident.Sensitivity), toRuleRange(incident.Plan.TargetTemperatureRange), toRuleRange(incident.Plan.TargetHumidityRange))
	version := recoveryPolicyVersion(incident)
	if at.IsZero() {
		at = s.now()
	}
	snapshot := store.RecoveryPolicySnapshot{Version: version, MinimumStableMinutes: int64(policy.MinimumStableDuration / time.Minute), MinimumReadings: policy.MinimumReadings, MaximumGapMinutes: int64(policy.MaximumGap / time.Minute), GeneratedAt: at}
	calc := rules.CalculateRecoveryProgress(recoveryReadings(incident), policy, version)
	if calc.LatestInterruption == "" {
		calc.LatestInterruption = incident.LatestObservationInterruption
	}
	view := RecoveryProgressView{Policy: snapshot, Progress: calc, StableMinutes: calc.StableMinutes, ValidReadings: calc.ValidReadings, RemainingReadings: calc.RemainingReadings, EarliestVerificationAt: calc.EarliestVerificationAt, SamplingStatus: "not_scheduled"}
	var latest *store.EnvironmentReading
	for i := range incident.Readings {
		r := &incident.Readings[i]
		if r.Phase == "recovery" && r.ObservationWindow == incident.CurrentObservationWindow && r.EligibleForRecovery {
			if latest == nil || r.CapturedAt.After(latest.CapturedAt) {
				latest = r
			}
		}
	}
	if latest != nil {
		due := latest.CapturedAt.Add(policy.MaximumGap)
		view.NextSampleDueAt = &due
		if at.After(due) {
			view.SamplingStatus = "overdue"
		} else {
			view.SamplingStatus = "on_time"
		}
	}
	segments := map[string]*ObservationSegmentView{}
	var previous *store.EnvironmentReading
	for _, r := range incident.Readings {
		if r.Phase != "recovery" || r.ObservationWindow != incident.CurrentObservationWindow {
			continue
		}
		key := fmt.Sprintf("%d/%d", r.ObservationWindow, r.ObservationSegment)
		seg := segments[key]
		if seg == nil {
			seg = &ObservationSegmentView{Window: r.ObservationWindow, Segment: r.ObservationSegment, TemperaturePeak: r.TemperatureCelsius, HumidityPeak: r.RelativeHumidityPercent}
			segments[key] = seg
		}
		if r.EligibleForRecovery {
			seg.ValidReadings++
			if previous != nil {
				gap := r.CapturedAt.Sub(previous.CapturedAt)
				if gap > 0 {
					seg.StableMinutes += int64(gap / time.Minute)
					if int64(gap/time.Minute) > seg.MaxGapMinutes {
						seg.MaxGapMinutes = int64(gap / time.Minute)
					}
				}
			}
			seg.TemperatureMean += r.TemperatureCelsius
			seg.HumidityMean += r.RelativeHumidityPercent
			if r.TemperatureCelsius > seg.TemperaturePeak {
				seg.TemperaturePeak = r.TemperatureCelsius
			}
			if r.RelativeHumidityPercent > seg.HumidityPeak {
				seg.HumidityPeak = r.RelativeHumidityPercent
			}
		} else {
			prev := time.Time{}
			if previous != nil {
				prev = previous.CapturedAt
			}
			item := ObservationInterruption{Window: r.ObservationWindow, Segment: r.ObservationSegment, Reason: r.ExclusionReason, At: r.CapturedAt}
			if !prev.IsZero() {
				item.PreviousAt = &prev
			}
			view.Interruptions = append(view.Interruptions, item)
			previous = nil
		}
		if r.EligibleForRecovery {
			copyR := r
			previous = &copyR
		}
	}
	for _, seg := range segments {
		if seg.ValidReadings > 0 {
			seg.TemperatureMean /= float64(seg.ValidReadings)
			seg.HumidityMean /= float64(seg.ValidReadings)
		}
		view.Segments = append(view.Segments, *seg)
	}
	sort.Slice(view.Segments, func(i, j int) bool { return view.Segments[i].Segment < view.Segments[j].Segment })
	return view, nil
}

type VerificationHistoryView struct {
	Rounds              []store.RecoveryVerification `json:"rounds"`
	FirstQualifiedRound int                          `json:"first_qualified_round,omitempty"`
	LatestFailedRound   int                          `json:"latest_failed_round,omitempty"`
	Suggestions         []string                     `json:"suggestions,omitempty"`
}

func (s *Service) VerificationHistory(incidentID string) (VerificationHistoryView, error) {
	incident, err := s.Get(incidentID)
	if err != nil {
		return VerificationHistoryView{}, err
	}
	view := VerificationHistoryView{Rounds: incident.Verifications}
	for _, v := range incident.Verifications {
		if v.Qualified && view.FirstQualifiedRound == 0 {
			view.FirstQualifiedRound = v.Round
		}
		if !v.Qualified {
			view.LatestFailedRound = v.Round
			for _, f := range v.FailureDetails {
				switch f.Code {
				case "THRESHOLD_EXCEEDED":
					view.Suggestions = append(view.Suggestions, "补充目标范围内读数")
				case "SENSOR_INVALID":
					view.Suggestions = append(view.Suggestions, "进行传感器现场复核或交接")
				case "SAMPLING_INTERRUPTED":
					view.Suggestions = append(view.Suggestions, "补采中断区段读数")
				case "STABILITY_INSUFFICIENT":
					view.Suggestions = append(view.Suggestions, "延长稳定观察窗口")
				}
			}
		}
	}
	return view, nil
}

type ReadinessView struct {
	Ready     bool                  `json:"ready"`
	CheckedAt time.Time             `json:"checked_at"`
	Checks    []rules.ReadinessItem `json:"checks"`
}

func readinessFor(incident *store.EnvironmentIncident, supervisor bool, now time.Time) ReadinessView {
	deviationsClear := true
	for _, execution := range incident.Executions {
		if execution.DeviationGate != "" && execution.DeviationGate != "clear" && execution.DeviationGate != "resolved_by_supplemental" {
			deviationsClear = false
		}
	}
	holdsClear := true
	holdFailures := []string{}
	for _, hold := range incident.ReopenHolds {
		for _, requirement := range hold.Requirements {
			if requirement.ResolvedAt == nil || !hold.ReviewDueAt.After(now) {
				holdsClear = false
				if requirement.ResolvedAt == nil {
					holdFailures = append(holdFailures, fmt.Sprintf("hold_id=%s requirement_id=%s 尚未补证", hold.HoldID, requirement.RequirementID))
				} else {
					holdFailures = append(holdFailures, fmt.Sprintf("hold_id=%s 已到期，请续期或补证", hold.HoldID))
				}
			}
		}
	}
	if holdsClear {
		for _, hold := range incident.ReopenHolds {
			if !hold.ReviewDueAt.After(now) {
				holdsClear = false
				holdFailures = append(holdFailures, fmt.Sprintf("hold_id=%s 已到期，请续期", hold.HoldID))
			}
		}
	}
	checks := []rules.ReadinessItem{
		{Code: "STATUS_GATE", Ready: incident.Status == store.StatusRecoveryPassed, Message: "事件状态必须为 recovery_passed"},
		{Code: "ROLE_GATE", Ready: supervisor, Message: "签署人必须为值班主管"},
		{Code: "INSPECTION_GATE", Ready: incident.Inspection != nil, Message: "必须完成现场复核"},
		{Code: "PLAN_REVIEW_GATE", Ready: incident.Plan != nil && incident.Plan.ReviewStatus == "approved", Message: "当前方案必须审核通过"},
		{Code: "EXECUTION_DEVIATION_GATE", Ready: incident.Execution != nil && deviationsClear, Message: "执行证据存在且偏差均已闭环"},
		{Code: "OBSERVATION_WINDOW_GATE", Ready: incident.CurrentObservationWindow > 0, Message: "当前观察窗口必须有效"},
		{Code: "RECOVERY_VERIFICATION_GATE", Ready: incident.Verification != nil && incident.Verification.Qualified && incident.Verification.ObservationWindow == incident.CurrentObservationWindow, Message: "当前观察窗口必须通过恢复验证"},
		{Code: "EVIDENCE_CHAIN_GATE", Ready: incident.Revision > 0 && len(incident.Readings) > 0, Message: "证据聚合与审计版本必须完整"},
		{Code: "REOPEN_HOLD_GATE", Ready: holdsClear, Message: func() string {
			if len(holdFailures) > 0 {
				return strings.Join(holdFailures, "；")
			}
			return "暂缓补证要求必须全部解决且复核期限有效"
		}()},
	}
	ready, checks := rules.Readiness(checks)
	return ReadinessView{Ready: ready, CheckedAt: now, Checks: checks}
}

func (s *Service) ReopenReadiness(incidentID, actorRole string) (ReadinessView, error) {
	incident, err := s.Get(incidentID)
	if err != nil {
		return ReadinessView{}, err
	}
	return readinessFor(incident, actorRole == "duty_supervisor", s.now()), nil
}

type PlaceReopenHoldInput struct {
	Meta         CommandMeta `json:"meta"`
	ReasonCode   string      `json:"reason_code"`
	Requirements []string    `json:"requirements"`
	ReviewDueAt  time.Time   `json:"review_due_at"`
}

func (s *Service) PlaceReopenHold(incidentID string, input PlaceReopenHoldInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Meta.ActorRole != "duty_supervisor" {
		return nil, false, precondition("仅值班主管可以暂缓重新开放")
	}
	validReasons := map[string]bool{"additional_calibration_evidence": true, "execution_evidence_gap": true, "conservation_review": true, "other_evidence": true}
	if !validReasons[input.ReasonCode] || len(nonBlank(input.Requirements)) == 0 || !input.ReviewDueAt.After(s.now()) {
		return nil, false, invalid("必须选择有效 reason_code、补证要求和未来复核期限")
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "place_reopen_hold", "reopen.held", input, func(incident *store.EnvironmentIncident) error {
		if incident.Status != store.StatusRecoveryPassed || incident.Verification == nil || !incident.Verification.Qualified {
			return precondition("仅恢复验证合格后可以暂缓重新开放")
		}
		requirements := make([]store.HoldRequirement, 0, len(input.Requirements))
		for _, description := range nonBlank(input.Requirements) {
			requirements = append(requirements, store.HoldRequirement{RequirementID: s.id("hold-requirement"), Description: description})
		}
		incident.ReopenHolds = append(incident.ReopenHolds, store.ReopenHold{HoldID: s.id("hold"), ReasonCode: input.ReasonCode, Requirements: requirements, ReviewDueAt: input.ReviewDueAt.UTC(), DecidedBy: input.Meta.ActorID, DecidedAt: now})
		return nil
	})
}

type ResolveHoldRequirementInput struct {
	Meta        CommandMeta `json:"meta"`
	Resolution  string      `json:"resolution"`
	EvidenceRef string      `json:"evidence_ref"`
}

type RenewReopenHoldInput struct {
	Meta        CommandMeta `json:"meta"`
	ReviewDueAt time.Time   `json:"review_due_at"`
}

func (s *Service) RenewReopenHold(incidentID, holdID string, input RenewReopenHoldInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Meta.ActorRole != "duty_supervisor" || !input.ReviewDueAt.After(s.now()) {
		return nil, false, precondition("仅值班主管可以提交未来复核期限")
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "renew_reopen_hold", "reopen.hold_renewed", input, func(incident *store.EnvironmentIncident) error {
		if incident.Status == store.StatusSealed {
			return precondition("事件已经封存，不能续期")
		}
		for i := range incident.ReopenHolds {
			if incident.ReopenHolds[i].HoldID == holdID {
				incident.ReopenHolds[i].ReviewDueAt = input.ReviewDueAt.UTC()
				incident.ReopenHolds[i].DecidedAt = now
				incident.ReopenHolds[i].DecidedBy = input.Meta.ActorID
				return nil
			}
		}
		return invalid("hold_id 不存在")
	})
}

func (s *Service) ResolveHoldRequirement(incidentID, holdID, requirementID string, input ResolveHoldRequirementInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if err := requireFields(map[string]string{"resolution": input.Resolution, "evidence_ref": input.EvidenceRef}); err != nil {
		return nil, false, err
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "resolve_reopen_hold", "reopen.hold_requirement_resolved", input, func(incident *store.EnvironmentIncident) error {
		for holdIndex := range incident.ReopenHolds {
			hold := &incident.ReopenHolds[holdIndex]
			if hold.HoldID != holdID {
				continue
			}
			for requirementIndex := range hold.Requirements {
				requirement := &hold.Requirements[requirementIndex]
				if requirement.RequirementID == requirementID {
					if requirement.ResolvedAt != nil {
						return precondition("补证要求已经解决")
					}
					requirement.ResolvedAt, requirement.Resolution, requirement.EvidenceRef, requirement.ResolvedBy = &now, strings.TrimSpace(input.Resolution), strings.TrimSpace(input.EvidenceRef), input.Meta.ActorID
					return nil
				}
			}
			return invalid("requirement_id 不存在")
		}
		return invalid("hold_id 不存在")
	})
}
