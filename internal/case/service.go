package cases

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"museumenv/internal/rules"
	"museumenv/internal/store"
)

type Repository interface {
	Create(store.Mutation, *store.EnvironmentIncident) (*store.EnvironmentIncident, bool, error)
	Update(store.Mutation, store.MutateFunc) (*store.EnvironmentIncident, bool, error)
	Get(string) (*store.EnvironmentIncident, error)
	List() ([]store.EnvironmentIncident, error)
	Query(store.IncidentQuery) (store.IncidentPage, error)
	Timeline(string) ([]store.AuditEvent, error)
	Evidence(string) (store.EvidenceSummary, error)
}

type Service struct {
	repository Repository
	now        func() time.Time
	id         func(string) string
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository, now: func() time.Time { return time.Now().UTC() }, id: randomID}
}

func randomID(prefix string) string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}

func reassessmentInterval(level rules.RiskLevel, sensitivity string) time.Duration {
	if level == rules.RiskCritical || strings.EqualFold(sensitivity, "high") {
		return 30 * time.Minute
	}
	if level == rules.RiskHigh || strings.EqualFold(sensitivity, "medium") {
		return 60 * time.Minute
	}
	return 2 * time.Hour
}
func maxFloat(v []float64) float64 {
	var m float64
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

type CommandMeta struct {
	RequestID        string `json:"request_id"`
	ActorID          string `json:"actor_id"`
	ActorRole        string `json:"actor_role"`
	ExpectedRevision int64  `json:"expected_revision"`
}

func validateMeta(meta CommandMeta, revisionRequired bool) error {
	if strings.TrimSpace(meta.RequestID) == "" {
		return invalid("request_id 不能为空")
	}
	if len(meta.RequestID) > 128 {
		return invalid("request_id 长度不能超过 128")
	}
	if strings.TrimSpace(meta.ActorID) == "" {
		return invalid("actor_id 不能为空")
	}
	if revisionRequired && meta.ExpectedRevision < 1 {
		return invalid("expected_revision 必须大于零")
	}
	return nil
}

type CreateIncidentInput struct {
	Meta                    CommandMeta    `json:"meta"`
	DisplayCaseID           string         `json:"display_case_id"`
	ArtifactID              string         `json:"artifact_id"`
	SensorID                string         `json:"sensor_id"`
	Sensitivity             string         `json:"sensitivity"`
	AbnormalSince           time.Time      `json:"abnormal_since"`
	TemperatureCelsius      float64        `json:"temperature_celsius"`
	RelativeHumidityPercent float64        `json:"relative_humidity_percent"`
	TargetTemperature       store.Range    `json:"target_temperature_range"`
	TargetHumidity          store.Range    `json:"target_humidity_range"`
	SensorStatus            string         `json:"sensor_status"`
	CalibrationReference    string         `json:"calibration_reference,omitempty"`
	CalibrationExpiresAt    *time.Time     `json:"calibration_expires_at,omitempty"`
	QualityNote             string         `json:"quality_note,omitempty"`
	Quality                 string         `json:"quality,omitempty"`
	DiscoveryReadings       []ReadingInput `json:"discovery_readings,omitempty"`
	ContextChangeReason     string         `json:"context_change_reason,omitempty"`
}

func (s *Service) CreateIncident(input CreateIncidentInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, false); err != nil {
		return nil, false, err
	}
	if err := requireFields(map[string]string{"display_case_id": input.DisplayCaseID, "artifact_id": input.ArtifactID, "sensor_id": input.SensorID}); err != nil {
		return nil, false, err
	}
	idPattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{1,63}$`)
	for name, value := range map[string]string{"display_case_id": input.DisplayCaseID, "artifact_id": input.ArtifactID, "sensor_id": input.SensorID} {
		if !idPattern.MatchString(strings.TrimSpace(value)) {
			return nil, false, invalidField(name, "编号格式无效")
		}
	}
	if input.AbnormalSince.IsZero() {
		return nil, false, invalid("abnormal_since 不能为空")
	}
	if len(input.DiscoveryReadings) > 100 {
		return nil, false, invalid("发现阶段读数批次不能超过 100 条")
	}
	input.DisplayCaseID = normalizeBusinessID(input.DisplayCaseID)
	input.ArtifactID = normalizeBusinessID(input.ArtifactID)
	input.SensorID = normalizeBusinessID(input.SensorID)
	// A changed sensor for the same cabinet/artifact requires an explicit reason.
	if prior, err := s.repository.List(); err == nil {
		for _, old := range prior {
			if old.DisplayCaseID == input.DisplayCaseID && old.ArtifactID == input.ArtifactID && old.SensorID != input.SensorID && old.Status == store.StatusSealed && strings.TrimSpace(input.ContextChangeReason) == "" {
				return nil, false, &Error{Code: "CONTEXT_BINDING_CONFLICT", Message: "展柜最近封存事件的传感器绑定不一致，必须提供上下文变更原因", Details: map[string]any{"sensor_id": old.SensorID, "incident_id": old.IncidentID}}
			}
		}
	}
	now := s.now()
	if input.AbnormalSince.After(now) {
		return nil, false, invalid("abnormal_since 不能晚于当前时间")
	}
	readInputs := input.DiscoveryReadings
	if len(readInputs) == 0 {
		if input.SensorStatus != "ok" && input.SensorStatus != "warning" {
			return nil, false, invalid("sensor_status 必须为 ok 或 warning")
		}
		readInputs = []ReadingInput{{CapturedAt: now, TemperatureCelsius: input.TemperatureCelsius, RelativeHumidityPercent: input.RelativeHumidityPercent, SensorStatus: input.SensorStatus}}
	}
	seenTimes := map[int64]bool{}
	previousTime := time.Time{}
	strictQuality := strings.TrimSpace(input.CalibrationReference) != "" || input.CalibrationExpiresAt != nil
	if strictQuality && strings.TrimSpace(input.CalibrationReference) == "" {
		return nil, false, invalidField("calibration_reference", "calibration_reference 不能为空")
	}
	if strictQuality && input.CalibrationExpiresAt == nil {
		return nil, false, invalidField("calibration_expires_at", "calibration_expires_at 不能为空")
	}
	if input.CalibrationExpiresAt != nil && !input.CalibrationExpiresAt.After(now) {
		return nil, false, invalidField("calibration_expires_at", "校准参考已过期")
	}
	for i, reading := range readInputs {
		if reading.CapturedAt.IsZero() || reading.CapturedAt.Before(input.AbnormalSince) || reading.CapturedAt.After(now) {
			return nil, false, invalid(fmt.Sprintf("第 %d 条发现读数采集时间必须位于异常开始至请求时刻之间", i+1))
		}
		if reading.SensorStatus != "ok" && reading.SensorStatus != "warning" {
			return nil, false, invalid(fmt.Sprintf("第 %d 条发现读数 sensor_status 必须为 ok 或 warning", i+1))
		}
		if err := validatePhysicalReading(reading); err != nil {
			return nil, false, err
		}
		if strictQuality {
			field := fmt.Sprintf("discovery_readings[%d]", i)
			if strings.TrimSpace(reading.Quality) == "" && strings.TrimSpace(reading.QualityNote) == "" {
				return nil, false, invalidField(field+".quality", "每条发现读数必须提供 quality 或 quality_note")
			}
			if reading.CalibrationReference != "" && !strings.EqualFold(strings.TrimSpace(reading.CalibrationReference), strings.TrimSpace(input.CalibrationReference)) {
				reading.Quality = "warning"
				reading.QualityNote = "校准参考与登记来源不一致"
			}
		}
		quality := strings.ToLower(strings.TrimSpace(reading.Quality))
		if quality != "" && quality != "ok" && quality != "warning" && quality != "low" {
			return nil, false, invalidField(fmt.Sprintf("discovery_readings[%d].quality", i), "quality 必须为 ok、warning 或 low")
		}
		if strictQuality && (reading.SensorStatus != "ok" || (!previousTime.IsZero() && reading.CapturedAt.Sub(previousTime) > 2*time.Hour)) {
			reading.Quality = "warning"
			if strings.TrimSpace(reading.QualityNote) == "" {
				reading.QualityNote = "传感器状态或采样间隔导致质量降低"
			}
		}
		if seenTimes[reading.CapturedAt.UnixNano()] {
			return nil, false, invalid("发现阶段读数时间戳不能重复")
		}
		if !previousTime.IsZero() && !reading.CapturedAt.After(previousTime) {
			return nil, false, invalid("发现阶段读数必须按采集时间严格递增")
		}
		seenTimes[reading.CapturedAt.UnixNano()] = true
		previousTime = reading.CapturedAt
		readInputs[i] = reading
	}
	incidentID := s.id("inc")
	readings := make([]store.EnvironmentReading, len(readInputs))
	ruleReadings := make([]rules.DiscoveryReading, len(readInputs))
	for i, value := range readInputs {
		if strings.TrimSpace(value.CalibrationReference) == "" {
			value.CalibrationReference = input.CalibrationReference
		}
		if strings.TrimSpace(value.QualityNote) == "" {
			value.QualityNote = input.QualityNote
		}
		if strings.TrimSpace(value.Quality) == "" {
			value.Quality = input.Quality
		}
		readings[i] = s.makeReading(incidentID, input.Meta.ActorID, "detection", value)
		readings[i].SensorID = input.SensorID
		ruleReadings[i] = rules.DiscoveryReading{ID: readings[i].ReadingID, CapturedAt: readings[i].CapturedAt, Temperature: readings[i].TemperatureCelsius, Humidity: readings[i].RelativeHumidityPercent, Quality: value.Quality, SensorStatus: value.SensorStatus}
	}
	spikes := rules.DetectIsolatedSpikes(ruleReadings)
	for i := range readings {
		if reason := spikes[readings[i].ReadingID]; reason != "" {
			readings[i].QualityFlag = "pending_review"
			readings[i].ReviewStatus = "pending"
			readings[i].ExclusionReason = reason
			ruleReadings[i].Quality = "warning"
		}
	}
	assessment, err := rules.AssessDiscoveryBatch(ruleReadings, toRuleRange(input.TargetTemperature), toRuleRange(input.TargetHumidity), input.AbnormalSince, now, rules.Sensitivity(input.Sensitivity))
	if err != nil {
		return nil, false, invalid(err.Error())
	}
	deadline := now.Add(assessment.ResponseWithin)
	initialEvaluation := store.RiskEvaluation{Sequence: 1, EvaluatedAt: now, RiskLevel: string(assessment.Level), RiskScore: assessment.Score, Reasons: assessment.Reasons, ResponseDeadline: deadline, PeakReadingID: assessment.PeakReadingID, Explanation: assessment.Explanation, TrendSlope: assessment.TrendSlope, DurationMinutes: int64(now.Sub(input.AbnormalSince) / time.Minute), EscalationReason: "初始登记基线评估"}
	baselineVersion := "baseline-" + now.UTC().Format("20060102T150405Z")
	incident := &store.EnvironmentIncident{IncidentID: incidentID, CaseNumber: "ME-" + now.Format("20060102") + "-" + strings.ToUpper(incidentID[len(incidentID)-6:]), DisplayCaseID: input.DisplayCaseID, ArtifactID: input.ArtifactID, SensorID: input.SensorID, CalibrationReference: strings.TrimSpace(input.CalibrationReference), CalibrationExpiresAt: input.CalibrationExpiresAt, BaselineVersion: baselineVersion, OpenedAt: now, AbnormalSince: input.AbnormalSince.UTC(), Sensitivity: input.Sensitivity, BaselineTemperature: input.TargetTemperature, BaselineHumidity: input.TargetHumidity, RiskLevel: string(assessment.Level), RiskScore: assessment.Score, RiskReasons: assessment.Reasons, ResponseDeadline: deadline, OriginalResponseDeadline: deadline, PeakReadingID: assessment.PeakReadingID, RiskExplanation: assessment.Explanation, InitialRiskEvaluation: initialEvaluation, RiskEvaluations: []store.RiskEvaluation{initialEvaluation}, Status: store.StatusReported, CreatedBy: input.Meta.ActorID, CurrentObservationWindow: 1, Readings: readings}
	incident.ContextSnapshots = []store.ContextSnapshot{{Version: 1, DisplayCaseID: input.DisplayCaseID, ArtifactID: input.ArtifactID, SensorID: input.SensorID, CalibrationReference: input.CalibrationReference, Validated: true, ValidationResult: "validated", ChangeReason: strings.TrimSpace(input.ContextChangeReason), CreatedAt: now}}
	incident.CurrentContextVersion = 1
	incident.ReassessmentTasks = []store.ReassessmentTask{{TaskID: s.id("reassess"), IncidentID: incidentID, DueAt: now.Add(reassessmentInterval(assessment.Level, input.Sensitivity)), Status: "pending", CreatedAt: now, RemainingMinutes: int64(reassessmentInterval(assessment.Level, input.Sensitivity) / time.Minute)}}
	m := store.Mutation{RequestID: input.Meta.RequestID, Operation: "create_incident", IncidentID: incidentID, ActorID: input.Meta.ActorID, EventType: "incident.reported", Payload: input}
	result, replayed, err := s.repository.Create(m, incident)
	if err != nil {
		return nil, false, translateStoreError(err)
	}
	return result, replayed, nil
}

type InspectionInput struct {
	Meta                  CommandMeta      `json:"meta"`
	Finding               string           `json:"finding"`
	CauseHypotheses       HypothesisInputs `json:"cause_hypotheses"`
	IsolationMeasure      string           `json:"isolation_measure"`
	IndependentReading    ReadingInput     `json:"independent_reading"`
	AlternativeMonitoring string           `json:"alternative_monitoring"`
	AlternativeReviewAt   *time.Time       `json:"alternative_review_at,omitempty"`
	IndependentReadings   []ReadingInput   `json:"independent_readings,omitempty"`
}

// AppendDiscoveryReadingsInput 用于现场复核前追加发现阶段读数。
type AppendDiscoveryReadingsInput struct {
	Meta              CommandMeta    `json:"meta"`
	Readings          []ReadingInput `json:"readings,omitempty"`
	DiscoveryReadings []ReadingInput `json:"discovery_readings,omitempty"`
}

type ReviewReadingInput struct {
	Meta       CommandMeta `json:"meta"`
	Conclusion string      `json:"conclusion"`
	Note       string      `json:"note,omitempty"`
}

func (s *Service) ReviewReading(incidentID, readingID string, input ReviewReadingInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	role := strings.ToLower(strings.TrimSpace(input.Meta.ActorRole))
	if role == "" || (role != "protective_personnel" && role != "preventive_conservator" && role != "conservation_engineer" && role != "duty_supervisor" && !strings.Contains(role, "protect")) {
		return nil, false, precondition("仅保护人员可以复核异常读数")
	}
	if input.Conclusion != "included" && input.Conclusion != "excluded" {
		return nil, false, invalid("conclusion 必须为 included 或 excluded")
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "review_reading", "reading.reviewed", input, func(incident *store.EnvironmentIncident) error {
		for i := range incident.Readings {
			r := &incident.Readings[i]
			if r.ReadingID != readingID {
				continue
			}
			if r.ReviewStatus != "pending" {
				return precondition("该读数已完成复核")
			}
			r.ReviewStatus, r.ReviewConclusion, r.ReviewedBy, r.ReviewedAt = "reviewed", input.Conclusion, input.Meta.ActorID, &now
			if input.Conclusion == "included" {
				r.EligibleForRecovery = true
				r.ExclusionReason = ""
				r.QualityFlag = "reviewed_included"
			} else {
				r.EligibleForRecovery = false
				r.ExclusionReason = "复核结论永久排除"
				r.QualityFlag = "excluded"
			}
			return nil
		}
		return invalid("reading_id 不存在")
	})
}

func (s *Service) AppendDiscoveryReadings(incidentID string, input AppendDiscoveryReadingsInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if len(input.Readings) == 0 {
		input.Readings = input.DiscoveryReadings
	}
	if len(input.Readings) == 0 || len(input.Readings) > 100 {
		return nil, false, invalid("补充读数批次必须为 1 至 100 条")
	}
	now := s.now()
	for i, reading := range input.Readings {
		if reading.CapturedAt.IsZero() || reading.CapturedAt.After(now) {
			return nil, false, invalid(fmt.Sprintf("第 %d 条补充读数时间无效", i+1))
		}
		if reading.SensorStatus != "ok" && reading.SensorStatus != "warning" {
			return nil, false, invalid(fmt.Sprintf("第 %d 条补充读数 sensor_status 必须为 ok 或 warning", i+1))
		}
		if err := validatePhysicalReading(reading); err != nil {
			return nil, false, err
		}
	}
	return s.update(incidentID, input.Meta, "append_discovery_readings", "incident.readings_appended", input, func(incident *store.EnvironmentIncident) error {
		if incident.Status != store.StatusReported || incident.Inspection != nil {
			return precondition("仅尚未完成现场复核的 reported 事件可以追加发现读数")
		}
		seen := map[int64]bool{}
		var previous time.Time
		for _, r := range incident.Readings {
			if r.Phase == "detection" {
				seen[r.CapturedAt.UnixNano()] = true
				if previous.IsZero() || r.CapturedAt.After(previous) {
					previous = r.CapturedAt
				}
			}
		}
		for i, r := range input.Readings {
			if seen[r.CapturedAt.UnixNano()] {
				return invalid("补充读数时间戳不能与批次内或历史读数重复")
			}
			if !previous.IsZero() && !r.CapturedAt.After(previous) {
				return invalid("补充读数必须按时间严格递增且晚于历史发现读数")
			}
			if i > 0 && !r.CapturedAt.After(input.Readings[i-1].CapturedAt) {
				return invalid("补充读数必须按采集时间严格递增")
			}
			seen[r.CapturedAt.UnixNano()] = true
			previous = r.CapturedAt
		}
		rulesReadings := make([]rules.DiscoveryReading, 0)
		for i := range incident.Readings {
			r := incident.Readings[i]
			if r.Phase == "detection" {
				rulesReadings = append(rulesReadings, rules.DiscoveryReading{ID: r.ReadingID, CapturedAt: r.CapturedAt, Temperature: r.TemperatureCelsius, Humidity: r.RelativeHumidityPercent, Quality: r.QualityFlag, SensorStatus: r.SensorStatus})
			}
		}
		for _, r := range input.Readings {
			item := s.makeReading(incidentID, input.Meta.ActorID, "detection", r)
			item.SensorID = incident.SensorID
			incident.Readings = append(incident.Readings, item)
			rulesReadings = append(rulesReadings, rules.DiscoveryReading{ID: item.ReadingID, CapturedAt: item.CapturedAt, Temperature: item.TemperatureCelsius, Humidity: item.RelativeHumidityPercent, Quality: item.QualityFlag, SensorStatus: item.SensorStatus})
		}
		spikes := rules.DetectIsolatedSpikes(rulesReadings)
		for i := range incident.Readings {
			if reason := spikes[incident.Readings[i].ReadingID]; reason != "" {
				incident.Readings[i].QualityFlag = "pending_review"
				incident.Readings[i].ReviewStatus = "pending"
				incident.Readings[i].ExclusionReason = reason
			}
		}
		assessment, err := rules.AssessDiscoveryBatch(rulesReadings, toRuleRange(incident.BaselineTemperature), toRuleRange(incident.BaselineHumidity), incident.AbnormalSince, now, rules.Sensitivity(incident.Sensitivity))
		if err != nil {
			return invalid(err.Error())
		}
		previousLevel, previousScore, previousDeadline := incident.RiskLevel, incident.RiskScore, incident.ResponseDeadline
		deadline := now.Add(assessment.ResponseWithin)
		if deadline.After(incident.ResponseDeadline) {
			deadline = incident.ResponseDeadline
		}
		// Risk level and deadline are monotonic for the incident, while every
		// evaluation (including a later decline) remains visible in history.
		if rules.RiskRank(assessment.Level) > rules.RiskRank(rules.RiskLevel(incident.RiskLevel)) || (assessment.Level == rules.RiskLevel(incident.RiskLevel) && assessment.Score >= incident.RiskScore) {
			incident.RiskLevel, incident.RiskScore, incident.RiskReasons, incident.PeakReadingID, incident.RiskExplanation = string(assessment.Level), assessment.Score, assessment.Reasons, assessment.PeakReadingID, assessment.Explanation
		}
		levelDelta := rules.RiskRank(assessment.Level) - rules.RiskRank(rules.RiskLevel(previousLevel))
		if rules.RiskRank(rules.RiskLevel(previousLevel)) > rules.RiskRank(rules.RiskLevel(incident.RiskLevel)) {
			levelDelta = rules.RiskRank(rules.RiskLevel(incident.RiskLevel)) - rules.RiskRank(rules.RiskLevel(previousLevel))
		}
		eval := store.RiskEvaluation{Sequence: len(incident.RiskEvaluations) + 1, EvaluatedAt: now, RiskLevel: string(assessment.Level), RiskScore: assessment.Score, Reasons: assessment.Reasons, ResponseDeadline: deadline, PeakReadingID: assessment.PeakReadingID, Explanation: assessment.Explanation, PreviousRiskLevel: previousLevel, PreviousRiskScore: previousScore, LevelDelta: levelDelta, ScoreDelta: assessment.Score - previousScore, DeadlineDeltaMinutes: int64(deadline.Sub(previousDeadline) / time.Minute), TrendSlope: assessment.TrendSlope, DurationMinutes: int64(now.Sub(incident.AbnormalSince) / time.Minute)}
		if levelDelta > 0 {
			eval.EscalationReason = "趋势恶化触发风险升级"
		} else if levelDelta < 0 {
			eval.EscalationReason = "补充读数显示风险回落，保留历史最高级别"
		} else {
			eval.EscalationReason = "风险级别保持"
		}
		incident.ResponseDeadline = deadline
		incident.RiskEvaluations = append(incident.RiskEvaluations, eval)
		hasPending := false
		for i := range incident.ReassessmentTasks {
			if incident.ReassessmentTasks[i].Status == "pending" {
				hasPending = true
				incident.ReassessmentTasks[i].RemainingMinutes = int64(incident.ReassessmentTasks[i].DueAt.Sub(now) / time.Minute)
			}
		}
		if !hasPending && incident.Status != store.StatusSealed {
			interval := reassessmentInterval(assessment.Level, incident.Sensitivity)
			incident.ReassessmentTasks = append(incident.ReassessmentTasks, store.ReassessmentTask{TaskID: s.id("reassess"), IncidentID: incident.IncidentID, DueAt: now.Add(interval), Status: "pending", RemainingMinutes: int64(interval / time.Minute), CreatedAt: now, EscalationReason: eval.EscalationReason})
		}
		return nil
	})
}

func (s *Service) RecordInspection(incidentID string, input InspectionInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(input.Finding) == "" {
		return nil, false, invalid("finding 不能为空")
	}
	if len(input.CauseHypotheses) == 0 {
		return nil, false, invalid("至少需要一项异常原因假设")
	}
	seenHypotheses := map[string]bool{}
	seenHypothesisIDs := map[string]bool{}
	confirmedCount := 0
	for _, hypothesis := range input.CauseHypotheses {
		key := strings.ToLower(strings.TrimSpace(hypothesis.Description))
		if key == "" || seenHypotheses[key] {
			return nil, false, invalid("异常原因假设不能为空或重复")
		}
		seenHypotheses[key] = true
		if hypothesis.HypothesisID != "" {
			if seenHypothesisIDs[hypothesis.HypothesisID] {
				return nil, false, invalid("hypothesis_id 不能重复")
			}
			seenHypothesisIDs[hypothesis.HypothesisID] = true
		}
		if hypothesis.Conclusion != "" && hypothesis.Conclusion != "pending" && hypothesis.Conclusion != "supported" && hypothesis.Conclusion != "excluded" {
			if hypothesis.Conclusion != "confirmed" {
				return nil, false, invalid("原因结论必须为 pending、supported、excluded 或 confirmed")
			}
		}
		if hypothesis.Conclusion == "supported" || hypothesis.Conclusion == "confirmed" {
			confirmedCount++
		}
		if hypothesis.Conclusion != "" && hypothesis.Conclusion != "pending" && (strings.TrimSpace(hypothesis.VerificationMethod) == "" || strings.TrimSpace(hypothesis.Evidence) == "") {
			return nil, false, invalid("支持或排除原因时必须提供验证方法和现场证据")
		}
	}
	if confirmedCount > 1 {
		return nil, false, &Error{Code: "CAUSE_HYPOTHESIS_CONFLICT", Message: "互斥假设不能同时确认", Details: map[string]any{"confirmed_count": confirmedCount}}
	}
	if len(input.IndependentReadings) > 0 {
		for i, reading := range input.IndependentReadings {
			if err := validateCalibration(reading, fmt.Sprintf("independent_readings[%d]", i)); err != nil {
				return nil, false, err
			}
		}
		input.IndependentReading = input.IndependentReadings[0]
	} else {
		if err := validateCalibration(input.IndependentReading, "independent_reading"); err != nil {
			return nil, false, err
		}
		input.IndependentReadings = []ReadingInput{input.IndependentReading}
	}
	now := s.now()
	if input.AlternativeReviewAt != nil && !input.AlternativeReviewAt.After(now) {
		return nil, false, invalid("alternative_review_at 必须晚于复核时刻")
	}
	return s.update(incidentID, input.Meta, "record_inspection", "inspection.recorded", input, func(incident *store.EnvironmentIncident) error {
		if err := requireStatus(incident, store.StatusReported); err != nil {
			return err
		}
		if input.IndependentReading.CapturedAt.Before(incident.AbnormalSince) {
			return invalid("独立仪表采集时间不得早于异常开始时间")
		}
		if input.IndependentReading.CapturedAt.After(now.Add(time.Minute)) {
			return invalid("独立仪表采集时间不能晚于当前时间")
		}
		sensor := incident.Readings[0]
		comparison := rules.CompareReadings(sensor.TemperatureCelsius, sensor.RelativeHumidityPercent, input.IndependentReading.TemperatureCelsius, input.IndependentReading.RelativeHumidityPercent)
		if !comparison.Trustworthy && strings.TrimSpace(input.IsolationMeasure) == "" && strings.TrimSpace(input.AlternativeMonitoring) == "" {
			return precondition("独立仪表与传感器差异超限，必须记录隔离或替代监测措施")
		}
		assessment, err := rules.AssessRisk(rules.RiskInput{Temperature: input.IndependentReading.TemperatureCelsius, Humidity: input.IndependentReading.RelativeHumidityPercent, TargetTemperature: toRuleRange(incident.BaselineTemperature), TargetHumidity: toRuleRange(incident.BaselineHumidity), Duration: now.Sub(incident.AbnormalSince), Sensitivity: rules.Sensitivity(incident.Sensitivity)})
		if err != nil {
			return invalid(err.Error())
		}
		oldRisk := incident.RiskLevel
		if rules.RiskRank(assessment.Level) >= rules.RiskRank(rules.RiskLevel(incident.RiskLevel)) {
			incident.RiskLevel = string(assessment.Level)
			incident.RiskScore = assessment.Score
			incident.RiskReasons = assessment.Reasons
		}
		candidateDeadline := now.Add(assessment.ResponseWithin)
		if candidateDeadline.Before(incident.ResponseDeadline) {
			incident.ResponseDeadline = candidateDeadline
		}
		if (incident.RiskLevel == string(rules.RiskHigh) || incident.RiskLevel == string(rules.RiskCritical)) && strings.TrimSpace(input.IsolationMeasure) == "" {
			return precondition("高风险或严重风险复核必须记录临时隔离措施")
		}
		independent := s.makeReading(incidentID, input.Meta.ActorID, "inspection", input.IndependentReading)
		independent.SensorID = incident.SensorID
		incident.Readings = append(incident.Readings, independent)
		legacyHypotheses := make([]string, 0, len(input.CauseHypotheses))
		structured := make([]store.CauseHypothesis, 0, len(input.CauseHypotheses))
		for _, value := range input.CauseHypotheses {
			description := strings.TrimSpace(value.Description)
			legacyHypotheses = append(legacyHypotheses, description)
			hypothesisID := value.HypothesisID
			if hypothesisID == "" {
				hypothesisID = s.id("hypothesis")
			}
			conclusion := value.Conclusion
			if conclusion == "" {
				conclusion = "pending"
			}
			item := store.CauseHypothesis{HypothesisID: hypothesisID, Description: description, CreatedBy: input.Meta.ActorID, CreatedAt: now, CurrentConclusion: conclusion}
			item.Conclusions = append(item.Conclusions, store.CauseConclusion{ConclusionID: s.id("conclusion"), HypothesisID: hypothesisID, Conclusion: conclusion, VerificationMethod: strings.TrimSpace(value.VerificationMethod), Evidence: strings.TrimSpace(value.Evidence), RecordedBy: input.Meta.ActorID, RecordedAt: now})
			structured = append(structured, item)
		}
		alternativeReviewAt := input.AlternativeReviewAt
		allIndependent := []store.EnvironmentReading{independent}
		tempDiffs, humDiffs := []float64{comparison.TemperatureDifference}, []float64{comparison.HumidityDifference}
		for _, extra := range input.IndependentReadings[1:] {
			rd := s.makeReading(incidentID, input.Meta.ActorID, "inspection", extra)
			rd.SensorID = incident.SensorID
			incident.Readings = append(incident.Readings, rd)
			allIndependent = append(allIndependent, rd)
			c := rules.CompareReadings(sensor.TemperatureCelsius, sensor.RelativeHumidityPercent, rd.TemperatureCelsius, rd.RelativeHumidityPercent)
			tempDiffs = append(tempDiffs, c.TemperatureDifference)
			humDiffs = append(humDiffs, c.HumidityDifference)
		}
		sort.Float64s(tempDiffs)
		sort.Float64s(humDiffs)
		trustworthy := tempDiffs[len(tempDiffs)/2] <= 2 && humDiffs[len(humDiffs)/2] <= 5
		incident.Inspection = &store.Inspection{CheckedAt: now, InspectorID: input.Meta.ActorID, Finding: strings.TrimSpace(input.Finding), CauseHypotheses: legacyHypotheses, Hypotheses: structured, IsolationMeasure: strings.TrimSpace(input.IsolationMeasure), IndependentReading: independent, IndependentReadings: allIndependent, AlternativeMonitoring: strings.TrimSpace(input.AlternativeMonitoring), AlternativeReviewAt: alternativeReviewAt, TemperatureDifference: comparison.TemperatureDifference, HumidityDifference: comparison.HumidityDifference, MedianTemperatureDifference: tempDiffs[len(tempDiffs)/2], MedianHumidityDifference: humDiffs[len(humDiffs)/2], MaximumTemperatureDifference: maxFloat(tempDiffs), MaximumHumidityDifference: maxFloat(humDiffs), ReportConclusion: map[bool]string{true: "trustworthy", false: "untrustworthy"}[trustworthy], SensorTrustworthy: trustworthy, RiskBefore: oldRisk, RiskAfter: incident.RiskLevel, ReassessmentReasons: assessment.Reasons}
		incident.Status = store.StatusInspected
		return nil
	})
}

type SubmitPlanInput struct {
	Meta                  CommandMeta                  `json:"meta"`
	ExpectedRevision      int64                        `json:"expected_revision,omitempty"`
	Steps                 []string                     `json:"steps"`
	TargetTemperature     store.Range                  `json:"target_temperature_range"`
	TargetHumidity        store.Range                  `json:"target_humidity_range"`
	IsolationRequired     bool                         `json:"isolation_required"`
	BaseVersion           int                          `json:"base_version"`
	CorrectionResolutions []store.CorrectionResolution `json:"correction_resolutions"`
	SafetyEnvelope        *store.SafetyEnvelope        `json:"safety_envelope,omitempty"`
	SafetyChangeNotes     map[string]string            `json:"safety_change_notes,omitempty"`
	Dependencies          map[int][]int                `json:"dependencies,omitempty"`
	PreflightVersion      int                          `json:"preflight_version,omitempty"`
}

// planSubmissionFailures reproduces every validation rule enforced by the
// submit-plan mutation callback so that PlanPreflight can detect the same
// rejections before callers attempt to submit. It must stay in sync with the
// failure paths in SubmitPlan; changes there must be mirrored here.
func planSubmissionFailures(incident *store.EnvironmentIncident, input SubmitPlanInput) []string {
	failures := rules.ValidatePlan(rules.PlanInput{Steps: input.Steps, TemperatureTarget: toRuleRange(input.TargetTemperature), HumidityTarget: toRuleRange(input.TargetHumidity), IsolationRequired: input.IsolationRequired, IsolationRecorded: incident.Inspection != nil && incident.Inspection.IsolationMeasure != "", RiskLevel: rules.RiskLevel(incident.RiskLevel)})
	failures = append(failures, rules.ValidatePlanDependencies(rules.PlanDependencyInput{Steps: input.Steps, Dependencies: input.Dependencies, IsolationRequired: input.IsolationRequired})...)
	if incident.Inspection == nil {
		failures = append(failures, "缺少现场原因假设")
	} else {
		hasSupported := false
		allPending := len(incident.Inspection.Hypotheses) > 0
		for _, hypothesis := range incident.Inspection.Hypotheses {
			if hypothesis.CurrentConclusion == "supported" || hypothesis.CurrentConclusion == "confirmed" {
				hasSupported = true
			}
			if hypothesis.CurrentConclusion != "pending" {
				allPending = false
			}
		}
		if !hasSupported && (!allPending || strings.TrimSpace(incident.Inspection.AlternativeMonitoring) == "" || incident.Inspection.AlternativeReviewAt == nil) {
			failures = append(failures, "尚无已支持原因；仅在全部原因待验证且已记录替代监测安排和复查时间时可继续")
		}
		if !incident.Inspection.SensorTrustworthy && len(incident.SensorHandovers) == 0 {
			failures = append(failures, "独立读数不可采纳且尚未完成可信传感器交接")
		}
		if strings.TrimSpace(incident.Inspection.IsolationMeasure) == "" {
			failures = append(failures, "缺少临时隔离措施")
		}
	}
	if input.SafetyEnvelope == nil {
		failures = append(failures, "必须提供 safety_envelope")
	} else {
		failures = append(failures, rules.ValidateSafetyEnvelope(toRuleSafety(*input.SafetyEnvelope), rules.Sensitivity(incident.Sensitivity), rules.RiskLevel(incident.RiskLevel))...)
	}
	for parameter, explanation := range input.SafetyChangeNotes {
		if strings.TrimSpace(parameter) == "" || strings.TrimSpace(explanation) == "" {
			failures = append(failures, "safety_change_notes 的参数名和变化说明不能为空")
		}
	}
	version := len(incident.PlanVersions) + 1
	if version > 1 {
		previous := incident.PlanVersions[len(incident.PlanVersions)-1]
		if previous.ReviewStatus != "rejected" || input.BaseVersion != previous.Version {
			failures = append(failures, "重提方案必须引用最新被退回版本")
		} else {
			resolved := map[string]bool{}
			duplicate := false
			for _, item := range input.CorrectionResolutions {
				if _, exists := resolved[item.RequirementID]; exists {
					duplicate = true
				}
				if strings.TrimSpace(item.Resolution) != "" && strings.TrimSpace(item.Evidence) != "" && item.Resolved {
					resolved[item.RequirementID] = true
				} else {
					resolved[item.RequirementID] = false
				}
			}
			if duplicate {
				failures = append(failures, "修正要求处理说明不能重复")
			}
			var missing []string
			for _, requirement := range previous.CorrectionRequirements {
				if !resolved[requirement.RequirementID] {
					missing = append(missing, requirement.Description)
				}
			}
			if len(missing) > 0 {
				failures = append(failures, "重提方案遗漏未解决修正要求："+strings.Join(missing, "；"))
			}
			if len(input.Steps) > len(previous.Steps) {
				failures = append(failures, "重提方案不得新增未审查步骤")
			}
			if input.SafetyEnvelope != nil && previous.SafetyEnvelope != nil && len(input.SafetyChangeNotes) == 0 && fmt.Sprintf("%+v", *input.SafetyEnvelope) != fmt.Sprintf("%+v", *previous.SafetyEnvelope) {
				failures = append(failures, "重提版本修改安全包络时必须逐项说明 safety_change_notes")
			}
		}
	} else if input.BaseVersion != 0 {
		failures = append(failures, "首版方案的 base_version 必须为 0")
	}
	return failures
}

func (s *Service) SubmitPlan(incidentID string, input SubmitPlanInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "submit_plan", "plan.submitted", input, func(incident *store.EnvironmentIncident) error {
		if input.PreflightVersion != 0 && input.PreflightVersion != int(incident.Revision) {
			return precondition("方案预检版本已过期，必须重新预检")
		}
		if incident.Status != store.StatusInspected && !(incident.Status == store.StatusPlanSubmitted && incident.Plan != nil && incident.Plan.ReviewStatus == "rejected") {
			return precondition("当前状态不允许提交干预方案")
		}
		failures := planSubmissionFailures(incident, input)
		if len(failures) > 0 {
			return invalid(strings.Join(failures, "；"))
		}
		version := len(incident.PlanVersions) + 1
		if version > 1 {
			resolved := map[string]bool{}
			for _, item := range input.CorrectionResolutions {
				if strings.TrimSpace(item.Resolution) != "" && strings.TrimSpace(item.Evidence) != "" && item.Resolved {
					resolved[item.RequirementID] = true
				} else {
					resolved[item.RequirementID] = false
				}
			}
			for i := range incident.PlanVersions[len(incident.PlanVersions)-1].CorrectionRequirements {
				requirement := &incident.PlanVersions[len(incident.PlanVersions)-1].CorrectionRequirements[i]
				if resolved[requirement.RequirementID] {
					completedAt := now
					requirement.CompletedAt = &completedAt
				}
			}
			incident.Plan = &incident.PlanVersions[len(incident.PlanVersions)-1]
		}
		plan := store.InterventionPlan{PlanID: s.id("plan"), IncidentID: incidentID, Steps: nonBlank(input.Steps), TargetTemperatureRange: input.TargetTemperature, TargetHumidityRange: input.TargetHumidity, IsolationRequired: input.IsolationRequired, SubmittedBy: input.Meta.ActorID, SubmittedAt: now, ReviewStatus: "pending", Version: version, BaseVersion: input.BaseVersion, CorrectionResolutions: input.CorrectionResolutions, SafetyEnvelope: input.SafetyEnvelope, SafetyChangeNotes: input.SafetyChangeNotes, PreflightVersion: input.PreflightVersion, PreflightPassed: input.PreflightVersion > 0, PreflightSummary: fmt.Sprintf("dependencies=%d", len(input.Dependencies))}
		incident.PlanVersions = append(incident.PlanVersions, plan)
		incident.Plan = &incident.PlanVersions[len(incident.PlanVersions)-1]
		incident.Status = store.StatusPlanSubmitted
		return nil
	})
}

type ReviewPlanInput struct {
	Meta                   CommandMeta                   `json:"meta"`
	Decision               string                        `json:"decision"`
	Note                   string                        `json:"note"`
	CorrectionRequirements []store.CorrectionRequirement `json:"correction_requirements"`
}

func (s *Service) ReviewPlan(incidentID string, input ReviewPlanInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Meta.ActorRole != "conservation_engineer" {
		return nil, false, precondition("仅保护工程师可以审核干预方案")
	}
	if input.Decision != "approve" && input.Decision != "reject" {
		return nil, false, invalid("decision 必须为 approve 或 reject")
	}
	if input.Decision == "reject" && len(input.CorrectionRequirements) == 0 {
		return nil, false, invalid("退回方案时必须记录至少一项结构化修正要求")
	}
	for i := range input.CorrectionRequirements {
		input.CorrectionRequirements[i].Description = strings.TrimSpace(input.CorrectionRequirements[i].Description)
		if input.CorrectionRequirements[i].Description == "" {
			return nil, false, invalid("修正要求说明不能为空")
		}
		if input.CorrectionRequirements[i].RequirementID == "" {
			input.CorrectionRequirements[i].RequirementID = s.id("correction")
		}
		if input.Decision == "reject" {
			if strings.TrimSpace(input.CorrectionRequirements[i].ResponsibleStep) == "" || strings.TrimSpace(input.CorrectionRequirements[i].RiskExplanation) == "" || strings.TrimSpace(input.CorrectionRequirements[i].EvidenceRequired) == "" {
				return nil, false, invalid("每项整改要求必须包含责任步骤、风险说明和完成证据")
			}
		}
	}
	seenRequirements := map[string]bool{}
	for _, item := range input.CorrectionRequirements {
		if seenRequirements[item.RequirementID] {
			return nil, false, invalid("修正要求 requirement_id 不能重复")
		}
		seenRequirements[item.RequirementID] = true
	}
	now := s.now()
	eventType := "plan.approved"
	if input.Decision == "reject" {
		eventType = "plan.rejected"
	}
	return s.update(incidentID, input.Meta, "review_plan", eventType, input, func(incident *store.EnvironmentIncident) error {
		if err := requireStatus(incident, store.StatusPlanSubmitted); err != nil {
			return err
		}
		if incident.Plan == nil {
			return precondition("缺少待审核干预方案")
		}
		if incident.Plan.SubmittedBy == input.Meta.ActorID {
			return precondition("审核人与当前版本提交人必须不同")
		}
		incident.Plan.ReviewerID, incident.Plan.ReviewNote, incident.Plan.ReviewedAt = input.Meta.ActorID, strings.TrimSpace(input.Note), &now
		if input.Decision == "reject" {
			incident.Plan.ReviewStatus = "rejected"
			incident.Plan.CorrectionRequirements = input.CorrectionRequirements
			incident.Status = store.StatusPlanSubmitted
		} else {
			incident.Plan.ReviewStatus = "approved"
			incident.Plan.SafetyFrozenAt = &now
			incident.Plan.SafetyReviewSummary = strings.TrimSpace(input.Note)
			incident.Status = store.StatusPlanApproved
		}
		incident.PlanVersions[len(incident.PlanVersions)-1] = *incident.Plan
		return nil
	})
}

type ReadingInput struct {
	CapturedAt              time.Time `json:"captured_at"`
	TemperatureCelsius      float64   `json:"temperature_celsius"`
	RelativeHumidityPercent float64   `json:"relative_humidity_percent"`
	SensorStatus            string    `json:"sensor_status"`
	CalibrationReference    string    `json:"calibration_reference"`
	QualityNote             string    `json:"quality_note"`
	Quality                 string    `json:"quality,omitempty"`
	SensorID                string    `json:"sensor_id,omitempty"`
}

type ExecuteInput struct {
	Meta                 CommandMeta                 `json:"meta"`
	ExecutedAt           time.Time                   `json:"executed_at"`
	Notes                string                      `json:"notes"`
	Materials            []store.MaterialUsage       `json:"materials"`
	CalibrationBefore    ReadingInput                `json:"calibration_before"`
	CalibrationAfter     ReadingInput                `json:"calibration_after"`
	StepResults          []store.StepExecutionResult `json:"step_results"`
	FailedVerificationID string                      `json:"failed_verification_id"`
	ReturnedDeviationID  string                      `json:"returned_deviation_id,omitempty"`
	DurationMinutes      int64                       `json:"duration_minutes,omitempty"`
	Deviations           []DeviationInput            `json:"deviations,omitempty"`
	PlanVersion          int                         `json:"plan_version,omitempty"`
	SafetyEnvelope       *store.SafetyEnvelope       `json:"safety_envelope,omitempty"`
}

func (s *Service) RecordExecution(incidentID string, input ExecuteInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.ExecutedAt.IsZero() {
		return nil, false, invalid("executed_at 不能为空")
	}
	if input.ExecutedAt.After(s.now().Add(time.Minute)) {
		return nil, false, invalid("executed_at 不能晚于当前时间")
	}
	if len(input.Materials) == 0 {
		return nil, false, invalid("至少需要登记一项耗材批次")
	}
	if err := validateCalibration(input.CalibrationBefore, "calibration_before"); err != nil {
		return nil, false, err
	}
	if err := validateCalibration(input.CalibrationAfter, "calibration_after"); err != nil {
		return nil, false, err
	}
	now := s.now()
	if all, err := s.repository.List(); err == nil {
		for _, other := range all {
			if other.IncidentID == incidentID {
				continue
			}
			for _, ex := range other.Executions {
				for _, existing := range ex.Materials {
					for _, incoming := range input.Materials {
						if strings.EqualFold(strings.TrimSpace(existing.BatchNumber), strings.TrimSpace(incoming.BatchNumber)) && (strings.TrimSpace(existing.Name) != strings.TrimSpace(incoming.Name) || !existing.ExpiresAt.Equal(incoming.ExpiresAt)) {
							return nil, false, &Error{Code: "MATERIAL_BATCH_METADATA_CONFLICT", Message: "耗材批次元数据与历史登记冲突", Details: map[string]any{"batch_number": incoming.BatchNumber, "incident_id": other.IncidentID}}
						}
					}
				}
			}
		}
	}
	operation, eventType := "record_execution", "intervention.executed"
	if strings.TrimSpace(input.FailedVerificationID) != "" || strings.TrimSpace(input.ReturnedDeviationID) != "" {
		operation, eventType = "record_supplemental_execution", "intervention.supplemented"
	}
	return s.update(incidentID, input.Meta, operation, eventType, input, func(incident *store.EnvironmentIncident) error {
		supplemental := strings.TrimSpace(input.FailedVerificationID) != "" || strings.TrimSpace(input.ReturnedDeviationID) != ""
		if strings.TrimSpace(input.ReturnedDeviationID) != "" {
			if strings.TrimSpace(input.FailedVerificationID) != "" {
				return invalid("failed_verification_id 与 returned_deviation_id 不能同时提供")
			}
			if incident.Status != store.StatusExecuted || incident.Execution == nil || incident.Execution.DeviationGate != "returned" {
				return precondition("仅偏差被退回且尚未进入观察的事件可补充执行")
			}
			found := false
			for _, deviation := range incident.Execution.Deviations {
				if deviation.DeviationID == input.ReturnedDeviationID && deviation.CurrentDecision == "returned" {
					found = true
				}
			}
			if !found {
				return precondition("returned_deviation_id 必须引用当前执行中被退回的偏差")
			}
		} else if supplemental {
			if incident.Status != store.StatusObserving {
				return precondition("仅观察中且最近验证失败的事件可补充干预")
			}
			if len(incident.Verifications) == 0 {
				return precondition("缺少可引用的失败验证")
			}
			latest := incident.Verifications[len(incident.Verifications)-1]
			if latest.Qualified || latest.VerificationID != input.FailedVerificationID {
				return precondition("补充干预必须引用最近一次失败验证")
			}
		} else if err := requireStatus(incident, store.StatusPlanApproved); err != nil {
			return err
		}
		if incident.Plan == nil || incident.Plan.ReviewStatus != "approved" {
			return precondition("干预方案尚未审核通过")
		}
		if input.PlanVersion != 0 && input.PlanVersion != incident.Plan.Version {
			return precondition("执行只能引用当前已审核方案版本")
		}
		if input.SafetyEnvelope != nil {
			if incident.Plan.SafetyEnvelope == nil || fmt.Sprintf("%+v", *input.SafetyEnvelope) != fmt.Sprintf("%+v", *incident.Plan.SafetyEnvelope) {
				return precondition("执行提交的安全包络与已冻结摘要不一致")
			}
		}
		steps := make([]rules.ExecutionStep, len(input.StepResults))
		for i, item := range input.StepResults {
			steps[i] = rules.ExecutionStep{Number: item.StepNumber, Result: item.Result, DeviationReason: item.DeviationReason}
		}
		for _, deviation := range input.Deviations {
			if deviation.Type == "step_reorder" {
				sort.Slice(steps, func(i, j int) bool { return steps[i].Number < steps[j].Number })
				break
			}
		}
		materials := make([]rules.ExecutionMaterial, len(input.Materials))
		for i, item := range input.Materials {
			present := false
			switch v := item.Quantity.(type) {
			case string:
				parts := strings.Fields(v)
				if len(parts) >= 2 {
					amount, parseErr := strconv.ParseFloat(parts[0], 64)
					present = parseErr == nil && amount > 0 && strings.TrimSpace(strings.Join(parts[1:], " ")) != ""
				}
			case float64:
				present = v > 0
			case int:
				present = v > 0
			}
			materials[i] = rules.ExecutionMaterial{Name: item.Name, Batch: item.BatchNumber, QuantityPresent: present, ExpiresAt: item.ExpiresAt}
		}
		failures := rules.CheckExecution(rules.ExecutionCheck{PlanSteps: incident.Plan.Steps, Steps: steps, Materials: materials, ExecutedAt: input.ExecutedAt, BeforeAt: input.CalibrationBefore.CapturedAt, AfterAt: input.CalibrationAfter.CapturedAt, BeforeTemperature: input.CalibrationBefore.TemperatureCelsius, AfterTemperature: input.CalibrationAfter.TemperatureCelsius, BeforeHumidity: input.CalibrationBefore.RelativeHumidityPercent, AfterHumidity: input.CalibrationAfter.RelativeHumidityPercent, BeforeReference: input.CalibrationBefore.CalibrationReference, AfterReference: input.CalibrationAfter.CalibrationReference})
		durationMinutes := input.DurationMinutes
		if durationMinutes == 0 {
			durationMinutes = int64(input.CalibrationAfter.CapturedAt.Sub(input.CalibrationBefore.CapturedAt) / time.Minute)
		}
		if incident.Plan.SafetyEnvelope != nil {
			failures = append(failures, rules.CheckEnvelopeExecution(toRuleSafety(*incident.Plan.SafetyEnvelope), rules.EnvelopeActual{DurationMinutes: durationMinutes, TemperatureBefore: input.CalibrationBefore.TemperatureCelsius, TemperatureAfter: input.CalibrationAfter.TemperatureCelsius, HumidityBefore: input.CalibrationBefore.RelativeHumidityPercent, HumidityAfter: input.CalibrationAfter.RelativeHumidityPercent})...)
		}
		driftReasons := []string{}
		otherFailures := failures[:0]
		for _, failure := range failures {
			if strings.Contains(failure, "校准温度漂移") || strings.Contains(failure, "校准湿度漂移") || strings.Contains(failure, "参考编号不一致") || strings.Contains(failure, "temperature_change_per_hour") || strings.Contains(failure, "humidity_change_per_hour") || strings.Contains(failure, "stop_temperature") || strings.Contains(failure, "stop_humidity") {
				driftReasons = append(driftReasons, failure)
			} else {
				otherFailures = append(otherFailures, failure)
			}
		}
		failures = otherFailures
		classifications := make([]string, len(input.Deviations))
		deviationSteps := map[int]bool{}
		for i, deviation := range input.Deviations {
			deviationSteps[deviation.PlanStepNumber] = true
			if strings.TrimSpace(deviation.Reason) == "" || strings.TrimSpace(deviation.ImmediateControl) == "" {
				failures = append(failures, fmt.Sprintf("第 %d 项偏差必须记录原因和即时控制措施", i+1))
				continue
			}
			classification, classifyErr := rules.ClassifyDeviation(rules.DeviationInput{Type: deviation.Type, PlanStepNumber: deviation.PlanStepNumber}, incident.Plan.Steps)
			if classifyErr != nil {
				failures = append(failures, classifyErr.Error())
			}
			classifications[i] = classification
		}
		for _, step := range input.StepResults {
			if step.Result == "skipped" && !deviationSteps[step.StepNumber] {
				failures = append(failures, fmt.Sprintf("跳过方案步骤 %d 必须登记结构化偏差", step.StepNumber))
			}
		}
		usedBatches := map[string]bool{}
		for _, execution := range incident.Executions {
			for _, material := range execution.Materials {
				usedBatches[strings.ToLower(strings.TrimSpace(material.BatchNumber))] = true
			}
		}
		for _, material := range input.Materials {
			if usedBatches[strings.ToLower(strings.TrimSpace(material.BatchNumber))] {
				failures = append(failures, "耗材批次 "+material.BatchNumber+" 已在本事件中登记")
			}
		}
		if len(failures) > 0 {
			return precondition(strings.Join(failures, "；"))
		}
		for i := range input.Materials {
			input.Materials[i].Name = strings.TrimSpace(input.Materials[i].Name)
			input.Materials[i].BatchNumber = strings.TrimSpace(input.Materials[i].BatchNumber)
		}
		before := s.makeReading(incidentID, input.Meta.ActorID, "calibration_before", input.CalibrationBefore)
		after := s.makeReading(incidentID, input.Meta.ActorID, "calibration_after", input.CalibrationAfter)
		before.SensorID, after.SensorID = incident.SensorID, incident.SensorID
		incident.Readings = append(incident.Readings, before, after)
		for i := range input.StepResults {
			input.StepResults[i].Step = incident.Plan.Steps[input.StepResults[i].StepNumber-1]
			input.StepResults[i].SafetyCritical = rules.IsSafetyCriticalStep(input.StepResults[i].Step)
		}
		deviations := make([]store.ExecutionDeviation, 0, len(input.Deviations)+1)
		gate := "clear"
		for i, value := range input.Deviations {
			decision := "accepted"
			if classifications[i] == "review_required" {
				decision, gate = "pending", "pending_review"
			}
			deviations = append(deviations, store.ExecutionDeviation{DeviationID: s.id("deviation"), Type: value.Type, Reason: strings.TrimSpace(value.Reason), ImmediateControl: strings.TrimSpace(value.ImmediateControl), PlanStepNumber: value.PlanStepNumber, Classification: classifications[i], RecordedBy: input.Meta.ActorID, RecordedAt: now, CurrentDecision: decision})
		}
		if len(driftReasons) > 0 {
			gate = "pending_review"
			deviations = append(deviations, store.ExecutionDeviation{DeviationID: s.id("deviation"), Type: "calibration_drift", Reason: strings.Join(driftReasons, "；"), ImmediateControl: "暂停进入观察并复核校准参考与安全包络", Classification: "review_required", RecordedBy: input.Meta.ActorID, RecordedAt: now, CurrentDecision: "pending"})
		}
		execution := store.Execution{ExecutionID: s.id("execution"), ExecutedAt: input.ExecutedAt.UTC(), OperatorID: input.Meta.ActorID, Notes: strings.TrimSpace(input.Notes), Materials: input.Materials, CalibrationBefore: before, CalibrationAfter: after, PlanVersion: incident.Plan.Version, StepResults: input.StepResults, CalibrationDifference: store.CalibrationDifference{Temperature: input.CalibrationAfter.TemperatureCelsius - input.CalibrationBefore.TemperatureCelsius, Humidity: input.CalibrationAfter.RelativeHumidityPercent - input.CalibrationBefore.RelativeHumidityPercent}, Supplemental: supplemental, FailedVerificationID: input.FailedVerificationID, ResolvesDeviationID: input.ReturnedDeviationID, DurationMinutes: durationMinutes, Deviations: deviations, DeviationGate: gate, CalibrationDrift: len(driftReasons) > 0, CalibrationDriftReason: strings.Join(driftReasons, "；")}
		if input.ReturnedDeviationID != "" && incident.Execution != nil {
			incident.Execution.DeviationGate = "resolved_by_supplemental"
			incident.Executions[len(incident.Executions)-1] = *incident.Execution
		}
		incident.Executions = append(incident.Executions, execution)
		incident.Execution = &incident.Executions[len(incident.Executions)-1]
		incident.Plan.ExecutedAt = &now
		incident.PlanVersions[len(incident.PlanVersions)-1] = *incident.Plan
		if strings.TrimSpace(input.FailedVerificationID) != "" {
			incident.CurrentObservationWindow++
			incident.Status = store.StatusExecuted
		} else {
			incident.Status = store.StatusExecuted
		}
		return nil
	})
}

type AddObservationInput struct {
	Meta         CommandMeta    `json:"meta"`
	Readings     []ReadingInput `json:"readings"`
	MakeupReason string         `json:"makeup_reason,omitempty"`
}

func (s *Service) AddObservations(incidentID string, input AddObservationInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if len(input.Readings) == 0 {
		return nil, false, invalid("至少需要一条恢复观察读数")
	}
	if len(input.Readings) > 100 {
		return nil, false, invalid("单批观察读数不能超过 100 条")
	}
	for _, reading := range input.Readings {
		if err := validateObservation(reading); err != nil {
			return nil, false, err
		}
	}
	return s.update(incidentID, input.Meta, "add_observations", "recovery.observed", input, func(incident *store.EnvironmentIncident) error {
		if incident.Status != store.StatusExecuted && incident.Status != store.StatusObserving && incident.Status != store.StatusRecoveryPassed {
			return precondition("当前状态不允许添加恢复观察读数")
		}
		if incident.Execution == nil {
			return precondition("缺少干预执行记录")
		}
		if incident.Plan == nil {
			return precondition("缺少已批准干预方案")
		}
		policy := rules.PolicyFor(rules.RiskLevel(incident.RiskLevel), rules.Sensitivity(incident.Sensitivity), toRuleRange(incident.Plan.TargetTemperatureRange), toRuleRange(incident.Plan.TargetHumidityRange))
		policyVersion := recoveryPolicyVersion(incident)
		incident.RecoveryPolicy = &store.RecoveryPolicySnapshot{Version: policyVersion, MinimumStableMinutes: int64(policy.MinimumStableDuration / time.Minute), MinimumReadings: policy.MinimumReadings, MaximumGapMinutes: int64(policy.MaximumGap / time.Minute), GeneratedAt: s.now()}
		if incident.Execution.DeviationGate != "" && incident.Execution.DeviationGate != "clear" {
			return precondition("存在未决或被退回的执行偏差，不能添加恢复观察读数")
		}
		if len(incident.Verifications) > 0 {
			latest := incident.Verifications[len(incident.Verifications)-1]
			if !latest.Qualified && latest.ObservationWindow == incident.CurrentObservationWindow {
				return precondition("当前观察窗口验证已失败，必须先完成补充干预")
			}
		}
		for _, value := range input.Readings {
			if value.SensorID != "" && normalizeBusinessID(value.SensorID) != incident.SensorID {
				return precondition("观察读数传感器与当前传感器不一致，必须先完成 sensor-handover")
			}
			if !value.CapturedAt.After(incident.Execution.ExecutedAt) {
				return invalid("恢复观察读数必须晚于干预执行时间")
			}
			if len(incident.SensorHandovers) > 0 && !value.CapturedAt.After(incident.SensorHandovers[len(incident.SensorHandovers)-1].InstalledAt) {
				return invalid("传感器交接后的恢复读数必须晚于新传感器安装时间")
			}
		}
		existing := []rules.ObservationPoint{}
		baseSegment := 1
		var latestObservation *store.EnvironmentReading
		allObservationTimes := map[int64]bool{}
		for _, value := range incident.Readings {
			if value.Phase == "recovery" {
				allObservationTimes[value.CapturedAt.UnixNano()] = true
			}
			if value.Phase == "recovery" && value.ObservationWindow == incident.CurrentObservationWindow {
				if value.ObservationSegment > baseSegment {
					baseSegment = value.ObservationSegment
				}
				existing = append(existing, rules.ObservationPoint{CapturedAt: value.CapturedAt, SensorStatus: value.SensorStatus, CalibrationReference: value.CalibrationReference, QualityNote: value.QualityNote})
				copyValue := value
				latestObservation = &copyValue
			}
		}
		if latestObservation != nil && latestObservation.SensorStatus == "ok" && !latestObservation.EligibleForRecovery {
			baseSegment++
		}
		for i, value := range input.Readings {
			if allObservationTimes[value.CapturedAt.UnixNano()] {
				return invalid(fmt.Sprintf("第 %d 条观察读数时间与历史观察窗口重复", i+1))
			}
		}
		incoming := make([]rules.ObservationPoint, len(input.Readings))
		for i, value := range input.Readings {
			incoming[i] = rules.ObservationPoint{CapturedAt: value.CapturedAt, SensorStatus: value.SensorStatus, CalibrationReference: value.CalibrationReference, QualityNote: value.QualityNote}
		}
		quality, failures := rules.CheckObservationBatch(existing, incoming, policy.MaximumGap)
		if len(failures) > 0 {
			return invalid(strings.Join(failures, "；"))
		}
		window := incident.CurrentObservationWindow
		segment := baseSegment
		previousCapturedAt := time.Time{}
		if latestObservation != nil {
			previousCapturedAt = latestObservation.CapturedAt
		}
		if latestObservation != nil && input.Readings[0].CapturedAt.Sub(previousCapturedAt) > policy.MaximumGap && strings.TrimSpace(input.MakeupReason) == "" {
			return invalid("采样超过最大间隔时必须填写补采原因")
		}
		for i, value := range input.Readings {
			if !previousCapturedAt.IsZero() && value.CapturedAt.Sub(previousCapturedAt) > policy.MaximumGap {
				window++
				segment = 1
				incident.LatestObservationInterruption = "采样间隔超过上限，已开始新的观察窗口"
				interruptedAt := value.CapturedAt.UTC()
				incident.LatestObservationInterruptedAt = &interruptedAt
			}
			if !policy.TemperatureTarget.Contains(value.TemperatureCelsius) || !policy.HumidityTarget.Contains(value.RelativeHumidityPercent) {
				quality[i].Eligible = false
				quality[i].ExclusionReason = "阈值超限读数不计入稳定窗口"
			}
			reading := s.makeReading(incidentID, input.Meta.ActorID, "recovery", value)
			reading.SensorID = incident.SensorID
			reading.ObservationWindow = window
			reading.ObservationSegment = segment
			reading.EligibleForRecovery = quality[i].Eligible
			reading.ExclusionReason = quality[i].ExclusionReason
			if strings.TrimSpace(input.MakeupReason) != "" {
				reading.QualityNote = "补采：" + strings.TrimSpace(input.MakeupReason)
			}
			reading.QualityNote = strings.TrimSpace(value.QualityNote)
			incident.Readings = append(incident.Readings, reading)
			if !quality[i].Eligible {
				segment++
			}
			previousCapturedAt = value.CapturedAt
		}
		incident.CurrentObservationWindow = window
		progress := rules.CalculateRecoveryProgress(recoveryReadings(incident), policy, policyVersion)
		if progress.LatestInterruption == "" {
			progress.LatestInterruption = incident.LatestObservationInterruption
		}
		incident.RecoveryProgress = &store.RecoveryProgressSummary{PolicyVersion: progress.PolicyVersion, StableMinutes: progress.StableMinutes, ValidReadings: progress.ValidReadings, RemainingMinutes: progress.RemainingMinutes, RemainingReadings: progress.RemainingReadings, LatestInterruption: progress.LatestInterruption, EarliestVerificationAt: progress.EarliestVerificationAt, Qualified: progress.Qualified}
		incident.Status = store.StatusObserving
		return nil
	})
}

type VerifyRecoveryInput struct {
	Meta                 CommandMeta `json:"meta"`
	MinimumStableMinutes int64       `json:"minimum_stable_minutes"`
	MinimumReadings      int         `json:"minimum_readings"`
}

func (s *Service) VerifyRecovery(incidentID string, input VerifyRecoveryInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.MinimumStableMinutes < 1 {
		return nil, false, invalid("minimum_stable_minutes 必须大于零")
	}
	if input.MinimumReadings < 2 {
		return nil, false, invalid("minimum_readings 必须至少为 2")
	}
	now := s.now()
	return s.update(incidentID, input.Meta, "verify_recovery", "recovery.verified", input, func(incident *store.EnvironmentIncident) error {
		if err := requireStatus(incident, store.StatusObserving); err != nil {
			return err
		}
		if incident.Plan == nil {
			return precondition("缺少干预方案")
		}
		policy := rules.PolicyFor(rules.RiskLevel(incident.RiskLevel), rules.Sensitivity(incident.Sensitivity), toRuleRange(incident.Plan.TargetTemperatureRange), toRuleRange(incident.Plan.TargetHumidityRange))
		if input.MinimumStableMinutes < int64(policy.MinimumStableDuration/time.Minute) {
			return invalid(fmt.Sprintf("minimum_stable_minutes 不能低于规则下限 %d", int64(policy.MinimumStableDuration/time.Minute)))
		}
		if input.MinimumReadings < policy.MinimumReadings {
			return invalid(fmt.Sprintf("minimum_readings 不能低于规则下限 %d", policy.MinimumReadings))
		}
		if len(incident.Verifications) > 0 {
			latest := incident.Verifications[len(incident.Verifications)-1]
			if !latest.Qualified && latest.ObservationWindow == incident.CurrentObservationWindow {
				return precondition("当前观察窗口验证已失败，必须先完成补充干预")
			}
		}
		var recovery []rules.RecoveryReading
		latestSegment := 0
		for _, reading := range incident.Readings {
			if reading.Phase == "recovery" && reading.ObservationWindow == incident.CurrentObservationWindow && reading.ObservationSegment > latestSegment {
				latestSegment = reading.ObservationSegment
			}
		}
		for _, reading := range incident.Readings {
			if reading.Phase == "recovery" && reading.ObservationWindow == incident.CurrentObservationWindow && reading.ObservationSegment == latestSegment && reading.EligibleForRecovery && (reading.SensorID == "" || reading.SensorID == incident.SensorID) {
				recovery = append(recovery, rules.RecoveryReading{CapturedAt: reading.CapturedAt, Temperature: reading.TemperatureCelsius, Humidity: reading.RelativeHumidityPercent, SensorOK: reading.SensorStatus == "ok"})
			}
		}
		policy.MinimumStableDuration = time.Duration(input.MinimumStableMinutes) * time.Minute
		policy.MinimumReadings = input.MinimumReadings
		result := rules.EvaluateRecovery(recovery, policy)
		details := make([]store.VerificationFailure, len(result.Failures))
		for i, message := range result.Failures {
			code := "STABILITY_INSUFFICIENT"
			if strings.Contains(message, "目标范围") {
				code = "THRESHOLD_EXCEEDED"
			} else if strings.Contains(message, "传感器") {
				code = "SENSOR_INVALID"
			} else if strings.Contains(message, "间隔") {
				code = "SAMPLING_INTERRUPTED"
			}
			details[i] = store.VerificationFailure{Code: code, Message: message}
		}
		verification := store.RecoveryVerification{VerificationID: s.id("verification"), Round: len(incident.Verifications) + 1, ObservationWindow: incident.CurrentObservationWindow, VerifiedAt: now, VerifiedBy: input.Meta.ActorID, Qualified: result.Qualified, StableMinutes: result.StableMinutes, Failures: result.Failures, FailureDetails: details, NeedsSupplementalIntervention: !result.Qualified}
		incident.Verifications = append(incident.Verifications, verification)
		incident.Verification = &incident.Verifications[len(incident.Verifications)-1]
		if result.Qualified {
			incident.Status = store.StatusRecoveryPassed
		}
		return nil
	})
}

type SignReopenInput struct {
	Meta     CommandMeta `json:"meta"`
	Decision string      `json:"decision"`
	Note     string      `json:"note"`
}

func (s *Service) SignReopen(incidentID string, input SignReopenInput) (*store.EnvironmentIncident, bool, error) {
	if err := validateMeta(input.Meta, true); err != nil {
		return nil, false, err
	}
	if input.Decision != "reopen" {
		return nil, false, invalid("decision 必须为 reopen")
	}
	now := s.now()
	auditTailDigest := ""
	if events, err := s.repository.Timeline(incidentID); err == nil && len(events) > 0 {
		auditTailDigest = events[len(events)-1].EventDigest
	}
	result, replayed, err := s.update(incidentID, input.Meta, "sign_reopen", "incident.sealed", input, func(incident *store.EnvironmentIncident) error {
		readiness := readinessFor(incident, input.Meta.ActorRole == "duty_supervisor", now)
		if !readiness.Ready {
			missing := make([]string, 0)
			for _, check := range readiness.Checks {
				if !check.Ready {
					missing = append(missing, check.Code+"："+check.Message)
				}
			}
			return precondition(strings.Join(missing, "；"))
		}
		failures := rules.CheckReopenGate(rules.ReopenGate{ReviewApproved: incident.Plan != nil && incident.Plan.ReviewStatus == "approved", ExecutionRecorded: incident.Execution != nil, RecoveryQualified: incident.Verification != nil && incident.Verification.Qualified, SupervisorRole: input.Meta.ActorRole == "duty_supervisor", AlreadySealed: incident.Status == store.StatusSealed})
		counts := map[string]int{"registration": 0, "reviews": 0, "observations": 0}
		windows := map[int]bool{}
		for _, reading := range incident.Readings {
			if reading.Phase == "detection" {
				counts["registration"]++
			}
			if reading.Phase == "recovery" {
				counts["observations"]++
				windows[reading.ObservationWindow] = true
			}
		}
		for _, plan := range incident.PlanVersions {
			if plan.ReviewStatus == "approved" || plan.ReviewStatus == "rejected" {
				counts["reviews"]++
			}
		}
		inspectionCount := 0
		if incident.Inspection != nil {
			inspectionCount = 1
		}
		failures = append(failures, rules.CheckEvidenceGate(rules.EvidenceGate{RegistrationReadings: counts["registration"], Inspections: inspectionCount, PlanVersions: len(incident.PlanVersions), PlanReviews: counts["reviews"], Executions: len(incident.Executions), ObservationWindows: len(windows), ObservationReadings: counts["observations"], Verifications: len(incident.Verifications), QualifiedVerification: incident.Verification != nil && incident.Verification.Qualified && incident.Verification.ObservationWindow == incident.CurrentObservationWindow})...)
		if len(failures) > 0 {
			return precondition(strings.Join(failures, "；"))
		}
		if err := requireStatus(incident, store.StatusRecoveryPassed); err != nil {
			return err
		}
		checks := make([]store.ReadinessCheck, len(readiness.Checks))
		for i, check := range readiness.Checks {
			checks[i] = store.ReadinessCheck{Code: check.Code, Ready: check.Ready, Message: check.Message}
		}
		incident.FinalReadinessSnapshot = &store.ReadinessSnapshot{CheckedAt: now, Ready: readiness.Ready, Checks: checks, Revision: incident.Revision, RiskLevel: incident.RiskLevel, ObservationWindow: incident.CurrentObservationWindow, AuditTailDigest: auditTailDigest}
		incident.ReopenDecision = &store.ReopenDecision{SignedAt: now, SupervisorID: input.Meta.ActorID, Decision: input.Decision, Note: strings.TrimSpace(input.Note)}
		incident.SealedAt = &now
		incident.Status = store.StatusSealed
		return nil
	})
	var domain *Error
	if errors.As(err, &domain) && domain.Code == "REVISION_CONFLICT" {
		return nil, false, precondition("预览 revision 已变化，请重新生成 reopen-preview")
	}
	return result, replayed, err
}

func (s *Service) Get(incidentID string) (*store.EnvironmentIncident, error) {
	result, err := s.repository.Get(incidentID)
	if err != nil {
		return nil, translateStoreError(err)
	}
	now := s.now()
	for i := range result.DeadlineCommitments {
		commitment := &result.DeadlineCommitments[i]
		switch {
		case commitment.CompletedAt != nil:
			commitment.Status = "completed"
		case commitment.InvalidatedAt != nil || !commitment.CommitmentDueAt.After(now):
			commitment.Status = "invalidated"
		default:
			commitment.Status = "effective"
		}
	}
	for i := range result.ReopenHolds {
		hold := &result.ReopenHolds[i]
		hold.Status = "effective"
		if !hold.ReviewDueAt.After(now) {
			hold.Status = "overdue"
		}
		resolved := true
		for _, requirement := range hold.Requirements {
			if requirement.ResolvedAt == nil {
				resolved = false
			}
		}
		if resolved && hold.Status != "overdue" {
			hold.Status = "resolved"
		}
	}
	commitment := activeDeadlineCommitment(result, now)
	assessment := rules.AssessEscalation(result.ResponseDeadline, now, result.Status == store.StatusSealed, commitment != nil)
	result.EscalationStatus = store.EscalationStatus(assessment.Status)
	result.RemainingMinutes = assessment.RemainingMinutes
	if commitment != nil {
		result.CommitmentOwnerID = commitment.OwnerID
	}
	return result, nil
}
func (s *Service) List() ([]store.EnvironmentIncident, error) {
	result, err := s.repository.List()
	if err != nil {
		return nil, translateStoreError(err)
	}
	return result, nil
}

type ListQuery struct {
	ArtifactID        string
	SensorID          string
	CaseNumber        string
	OpenedFrom        time.Time
	OpenedTo          time.Time
	Statuses          []store.Status
	RiskLevels        []string
	DisplayCaseID     string
	DeadlineStatus    store.DeadlineStatus
	EscalationStatus  store.EscalationStatus
	CommitmentOwnerID string
	EvidenceGap       string
	Stats             bool
	Limit             int
	Cursor            string
}

func (s *Service) Query(input ListQuery) (store.IncidentPage, error) {
	if input.Limit == 0 {
		input.Limit = 50
	}
	if input.Limit < 1 || input.Limit > 100 {
		return store.IncidentPage{}, invalid("limit 必须在 1 至 100 之间")
	}
	validStatus := map[store.Status]bool{store.StatusReported: true, store.StatusInspected: true, store.StatusPlanSubmitted: true, store.StatusPlanApproved: true, store.StatusExecuted: true, store.StatusObserving: true, store.StatusRecoveryPassed: true, store.StatusSealed: true}
	for _, value := range input.Statuses {
		if !validStatus[value] {
			return store.IncidentPage{}, invalid("未知 status 筛选值：" + string(value))
		}
	}
	validRisk := map[string]bool{"low": true, "moderate": true, "high": true, "critical": true}
	for _, value := range input.RiskLevels {
		if !validRisk[value] {
			return store.IncidentPage{}, invalid("未知 risk_level 筛选值：" + value)
		}
	}
	if input.DeadlineStatus != "" && input.DeadlineStatus != store.DeadlineNormal && input.DeadlineStatus != store.DeadlineDueSoon && input.DeadlineStatus != store.DeadlineOverdue && input.DeadlineStatus != store.DeadlineArchived {
		return store.IncidentPage{}, invalid("未知 deadline_status 筛选值")
	}
	validEscalation := map[store.EscalationStatus]bool{store.EscalationNormal: true, store.EscalationDueSoon: true, store.EscalationOverdueUnacknowledged: true, store.EscalationOverdueAcknowledged: true, store.EscalationArchived: true}
	if input.EscalationStatus != "" && !validEscalation[input.EscalationStatus] {
		return store.IncidentPage{}, invalid("未知 escalation_status 筛选值")
	}
	if len(input.Statuses) == 0 && !input.Stats {
		if input.DeadlineStatus == store.DeadlineArchived || input.EscalationStatus == store.EscalationArchived {
			input.Statuses = []store.Status{store.StatusSealed}
		} else {
			input.Statuses = []store.Status{store.StatusReported, store.StatusInspected, store.StatusPlanSubmitted, store.StatusPlanApproved, store.StatusExecuted, store.StatusObserving, store.StatusRecoveryPassed}
		}
	}
	if input.EvidenceGap != "" {
		validGap := map[string]bool{"REGISTRATION_MISSING": true, "INSPECTION_MISSING": true, "PLAN_REVIEW_MISSING": true, "EXECUTION_MISSING": true, "OBSERVATION_MISSING": true, "VERIFICATION_MISSING": true, "REGISTRATION_AUDIT_MISSING": true, "INSPECTION_AUDIT_MISSING": true, "PLAN_REVIEW_AUDIT_MISSING": true, "EXECUTION_AUDIT_MISSING": true, "OBSERVATION_AUDIT_MISSING": true, "VERIFICATION_AUDIT_MISSING": true, "SEAL_AUDIT_MISSING": true}
		if !validGap[input.EvidenceGap] {
			return store.IncidentPage{}, invalid("未知 evidence_gap 筛选值")
		}
	}
	if !input.OpenedFrom.IsZero() && !input.OpenedTo.IsZero() && input.OpenedFrom.After(input.OpenedTo) {
		return store.IncidentPage{}, invalid("opened_at 时间范围无效")
	}
	page, err := s.repository.Query(store.IncidentQuery{ArtifactID: input.ArtifactID, SensorID: input.SensorID, CaseNumber: input.CaseNumber, OpenedFrom: input.OpenedFrom, OpenedTo: input.OpenedTo, Statuses: input.Statuses, RiskLevels: input.RiskLevels, DisplayCaseID: input.DisplayCaseID, DeadlineStatus: input.DeadlineStatus, EscalationStatus: input.EscalationStatus, CommitmentOwnerID: input.CommitmentOwnerID, EvidenceGap: input.EvidenceGap, Stats: input.Stats, Now: s.now(), Limit: input.Limit, Cursor: input.Cursor})
	if err != nil {
		return store.IncidentPage{}, invalid("cursor 无效或已过期")
	}
	return page, nil
}
func (s *Service) Timeline(id string) ([]store.AuditEvent, error) {
	result, err := s.repository.Timeline(id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	incident, getErr := s.Get(id)
	if getErr == nil {
		statuses := map[string]string{}
		for _, commitment := range incident.DeadlineCommitments {
			statuses[commitment.CommitmentID] = commitment.Status
		}
		for i := range result {
			value, ok := result[i].Details["commitment"].(map[string]any)
			if !ok {
				continue
			}
			commitmentID, _ := value["commitment_id"].(string)
			if status := statuses[commitmentID]; status != "" {
				value["status"] = status
			}
		}
	}
	return result, nil
}

type TimelineQuery struct {
	EventType, ActorID string
	From, To           time.Time
	Limit              int
	Cursor             string
}
type TimelinePage struct {
	Events       []store.AuditEvent `json:"events"`
	NextCursor   string             `json:"next_cursor,omitempty"`
	MatchCount   int                `json:"match_count"`
	EvidenceGaps []string           `json:"evidence_gaps,omitempty"`
}

func (s *Service) TimelinePage(id string, query TimelineQuery) (TimelinePage, error) {
	events, err := s.Timeline(id)
	if err != nil {
		return TimelinePage{}, err
	}
	previous := ""
	for i, e := range events {
		if i > 0 && e.PreviousDigest != previous {
			return TimelinePage{}, &Error{Code: "EVIDENCE_INTEGRITY_FAILED", Message: "审计摘要链连续性校验失败"}
		}
		previous = e.EventDigest
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		e.Details["event_label"] = eventLabel(e.EventType)
		events[i] = e
	}
	filtered := make([]store.AuditEvent, 0)
	for _, e := range events {
		if query.EventType != "" && e.EventType != query.EventType {
			continue
		}
		if query.ActorID != "" && e.ActorID != query.ActorID {
			continue
		}
		if !query.From.IsZero() && e.OccurredAt.Before(query.From) {
			continue
		}
		if !query.To.IsZero() && e.OccurredAt.After(query.To) {
			continue
		}
		filtered = append(filtered, e)
	}
	if query.Limit == 0 {
		query.Limit = 50
	}
	if query.Limit < 1 || query.Limit > 100 {
		return TimelinePage{}, invalid("limit 必须在 1 至 100 之间")
	}
	start := 0
	if query.Cursor != "" {
		found := false
		for i, e := range filtered {
			if e.EventID == query.Cursor {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return TimelinePage{}, invalid("cursor 无效")
		}
	}
	end := start + query.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := TimelinePage{Events: filtered[start:end], MatchCount: len(filtered), EvidenceGaps: timelineGaps(events)}
	if end < len(filtered) {
		page.NextCursor = filtered[end-1].EventID
	}
	return page, nil
}

func eventLabel(eventType string) string {
	labels := map[string]string{"incident.reported": "异常登记", "incident.readings_appended": "补充发现读数", "inspection.recorded": "现场复核", "sensor.handed_over": "传感器交接", "plan.submitted": "方案提交", "plan.approved": "方案审核通过", "plan.rejected": "方案退回", "intervention.executed": "干预执行", "intervention.supplemented": "补充干预执行", "recovery.observed": "恢复观察", "recovery.verified": "恢复验证", "reopen.held": "重新开放暂缓", "reopen.hold_requirement_resolved": "补证要求解决", "reopen.hold_renewed": "暂缓期限续期", "incident.sealed": "重新开放签署"}
	if value := labels[eventType]; value != "" {
		return value
	}
	return eventType
}
func timelineGaps(events []store.AuditEvent) []string {
	gaps := []string{}
	if len(events) == 0 {
		return append(gaps, "AUDIT_EMPTY")
	}
	types := map[string]bool{}
	for _, e := range events {
		types[e.EventType] = true
	}
	for key, code := range map[string]string{"incident.reported": "REGISTRATION_MISSING", "inspection.recorded": "INSPECTION_MISSING", "plan.approved": "PLAN_REVIEW_MISSING", "intervention.executed": "EXECUTION_MISSING", "recovery.observed": "OBSERVATION_MISSING", "recovery.verified": "VERIFICATION_MISSING", "reopen.held": "REOPEN_HOLD_MISSING"} {
		if !types[key] {
			gaps = append(gaps, code)
		}
	}
	sort.Strings(gaps)
	return gaps
}
func (s *Service) Evidence(id string) (store.EvidenceSummary, error) {
	result, err := s.repository.Evidence(id)
	if err != nil {
		return store.EvidenceSummary{}, translateStoreError(err)
	}
	return result, nil
}

func (s *Service) update(id string, meta CommandMeta, operation, event string, payload any, mutate store.MutateFunc) (*store.EnvironmentIncident, bool, error) {
	if strings.TrimSpace(id) == "" {
		return nil, false, invalid("incident_id 不能为空")
	}
	m := store.Mutation{RequestID: meta.RequestID, Operation: operation, IncidentID: id, ActorID: meta.ActorID, ExpectedRevision: meta.ExpectedRevision, EventType: event, Payload: payload}
	result, replayed, err := s.repository.Update(m, mutate)
	if err != nil {
		return nil, false, translateStoreError(err)
	}
	return result, replayed, nil
}

func (s *Service) makeReading(incidentID, actor, phase string, input ReadingInput) store.EnvironmentReading {
	quality := strings.ToLower(strings.TrimSpace(input.Quality))
	if quality == "" {
		if input.SensorStatus == "ok" {
			quality = "ok"
		} else {
			quality = "warning"
		}
	}
	score := 0
	if quality == "ok" {
		score = 100
	} else if quality == "warning" {
		score = 50
	}
	return store.EnvironmentReading{ReadingID: s.id("read"), IncidentID: incidentID, CapturedAt: input.CapturedAt.UTC(), TemperatureCelsius: input.TemperatureCelsius, RelativeHumidityPercent: input.RelativeHumidityPercent, SensorStatus: input.SensorStatus, CalibrationReference: strings.TrimSpace(input.CalibrationReference), OperatorID: actor, Phase: phase, QualityFlag: quality, QualityScore: score, QualityNote: strings.TrimSpace(input.QualityNote)}
}

func validateCalibration(reading ReadingInput, name string) error {
	if reading.CapturedAt.IsZero() {
		return invalid(name + ".captured_at 不能为空")
	}
	if reading.SensorStatus != "ok" {
		return invalid(name + ".sensor_status 必须为 ok")
	}
	if strings.TrimSpace(reading.CalibrationReference) == "" {
		return invalid(name + ".calibration_reference 不能为空")
	}
	return validatePhysicalReading(reading)
}

func validateObservation(reading ReadingInput) error {
	if reading.CapturedAt.IsZero() {
		return invalid("观察读数 captured_at 不能为空")
	}
	if reading.SensorStatus != "ok" && reading.SensorStatus != "warning" {
		return invalid("观察读数 sensor_status 必须为 ok 或 warning")
	}
	return validatePhysicalReading(reading)
}

func validatePhysicalReading(reading ReadingInput) error {
	if reading.TemperatureCelsius < -20 || reading.TemperatureCelsius > 60 {
		return invalid("温度读数超出可接受物理范围")
	}
	if reading.RelativeHumidityPercent < 0 || reading.RelativeHumidityPercent > 100 {
		return invalid("相对湿度读数必须在 0 至 100 之间")
	}
	return nil
}

func requireStatus(incident *store.EnvironmentIncident, expected store.Status) error {
	if incident.Status == store.StatusSealed {
		return precondition("事件已经封存，不能继续修改")
	}
	if incident.Status != expected {
		return precondition(fmt.Sprintf("当前状态 %s 不允许执行该操作，需要状态 %s", incident.Status, expected))
	}
	return nil
}

func requireFields(values map[string]string) error {
	for name, value := range values {
		if strings.TrimSpace(value) == "" {
			return invalid(name + " 不能为空")
		}
	}
	return nil
}

func nonBlank(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func normalizeBusinessID(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), "-"))
}

func toRuleRange(value store.Range) rules.Range { return rules.Range{Min: value.Min, Max: value.Max} }
