package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound         = errors.New("incident not found")
	ErrRevisionConflict = errors.New("revision conflict")
	ErrAlreadyExists    = errors.New("incident already exists")
	ErrSealed           = errors.New("incident sealed")
)

type ActiveIncidentError struct {
	IncidentID string
	CaseNumber string
	Status     Status
	Revision   int64
}

func (e *ActiveIncidentError) Error() string { return "同一展柜与传感器已有未封存事件" }

type persistedState struct {
	SchemaVersion  int                             `json:"schema_version"`
	Incidents      map[string]*EnvironmentIncident `json:"incidents"`
	CaseNumbers    map[string]string               `json:"case_numbers"`
	Commands       map[string]CommandResult        `json:"commands"`
	Audits         []AuditEvent                    `json:"audits"`
	ActiveContexts map[string]string               `json:"active_contexts"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state persistedState
	now   func() time.Time
}

type Mutation struct {
	RequestID        string
	Operation        string
	IncidentID       string
	ActorID          string
	ExpectedRevision int64
	EventType        string
	Payload          any
}

type IncidentQuery struct {
	ArtifactID        string
	SensorID          string
	CaseNumber        string
	OpenedFrom        time.Time
	OpenedTo          time.Time
	Statuses          []Status
	RiskLevels        []string
	DisplayCaseID     string
	DeadlineStatus    DeadlineStatus
	EscalationStatus  EscalationStatus
	CommitmentOwnerID string
	EvidenceGap       string
	Stats             bool
	Now               time.Time
	Limit             int
	Cursor            string
}

type IncidentPage struct {
	Items            []IncidentListItem
	NextCursor       string
	DeadlineCounts   map[DeadlineStatus]int
	EscalationCounts map[EscalationStatus]int
	Stats            *IncidentStats
}

type IncidentStats struct {
	GeneratedAt                    time.Time      `json:"generated_at"`
	IncidentCount                  int            `json:"incident_count"`
	OverdueCount                   int            `json:"overdue_count"`
	SealedCount                    int            `json:"sealed_count"`
	SealedRate                     float64        `json:"sealed_rate"`
	AverageHandlingMinutes         float64        `json:"average_handling_minutes"`
	EvidenceGapIncidentIDs         []string       `json:"evidence_gap_incident_ids,omitempty"`
	EvidenceGapIncidentCaseNumbers []string       `json:"evidence_gap_incident_case_numbers,omitempty"`
	EvidenceGapCounts              map[string]int `json:"evidence_gap_counts,omitempty"`
	ByDisplayCase                  map[string]int `json:"by_display_case,omitempty"`
	ByRiskLevel                    map[string]int `json:"by_risk_level,omitempty"`
	ByStatus                       map[Status]int `json:"by_status,omitempty"`
}

type MutateFunc func(*EnvironmentIncident) error

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("数据文件路径不能为空")
	}
	s := &Store{path: path, now: func() time.Time { return time.Now().UTC() }}
	s.state = persistedState{SchemaVersion: 3, Incidents: map[string]*EnvironmentIncident{}, CaseNumbers: map[string]string{}, Commands: map[string]CommandResult{}, ActiveContexts: map[string]string{}}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取数据文件: %w", err)
	}
	if err == nil {
		if len(data) == 0 {
			return nil, fmt.Errorf("数据文件为空")
		}
		if err := json.Unmarshal(data, &s.state); err != nil {
			return nil, fmt.Errorf("解析数据文件: %w", err)
		}
		s.normalize()
		if err := verifyAuditChain(s.state.Audits); err != nil {
			return nil, fmt.Errorf("审计链校验失败: %w", err)
		}
		if err := s.rebuildAndValidateActiveContexts(); err != nil {
			return nil, fmt.Errorf("在途上下文索引校验失败: %w", err)
		}
	}
	return s, nil
}

func (s *Store) normalize() {
	if s.state.SchemaVersion < 3 {
		s.state.SchemaVersion = 3
	}
	if s.state.Incidents == nil {
		s.state.Incidents = map[string]*EnvironmentIncident{}
	}
	if s.state.CaseNumbers == nil {
		s.state.CaseNumbers = map[string]string{}
	}
	if s.state.Commands == nil {
		s.state.Commands = map[string]CommandResult{}
	}
	if s.state.ActiveContexts == nil {
		s.state.ActiveContexts = map[string]string{}
	}
	for _, incident := range s.state.Incidents {
		if incident.OriginalResponseDeadline.IsZero() {
			incident.OriginalResponseDeadline = incident.ResponseDeadline
		}
		if len(incident.RiskEvaluations) == 0 && !incident.InitialRiskEvaluation.EvaluatedAt.IsZero() {
			incident.RiskEvaluations = []RiskEvaluation{incident.InitialRiskEvaluation}
		}
		for i := range incident.RiskEvaluations {
			incident.RiskEvaluations[i].Sequence = i + 1
		}
		if len(incident.RiskEvaluations) > 0 {
			incident.InitialRiskEvaluation.Sequence = 1
		}
		for i := range incident.Readings {
			if incident.Readings[i].SensorID == "" {
				incident.Readings[i].SensorID = incident.SensorID
			}
		}
	}
}

func normalizeIdentifier(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func activeContextKey(displayCaseID, sensorID string) string {
	return normalizeIdentifier(displayCaseID) + "\x00" + normalizeIdentifier(sensorID)
}

func (s *Store) rebuildAndValidateActiveContexts() error {
	rebuilt := make(map[string]string)
	for id, incident := range s.state.Incidents {
		if incident.Status == StatusSealed {
			continue
		}
		key := activeContextKey(incident.DisplayCaseID, incident.SensorID)
		if previous := rebuilt[key]; previous != "" && previous != id {
			return fmt.Errorf("事件 %s 与 %s 的在途上下文重复", previous, id)
		}
		rebuilt[key] = id
	}
	for key, id := range s.state.ActiveContexts {
		if rebuilt[key] != id {
			return fmt.Errorf("索引 %q 指向 %s，与快照不一致", key, id)
		}
	}
	s.state.ActiveContexts = rebuilt
	return nil
}

func commandKey(requestID string) string { return requestID }

func (s *Store) Create(m Mutation, incident *EnvironmentIncident) (*EnvironmentIncident, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.state.Commands[commandKey(m.RequestID)]; ok {
		if previous.Operation != m.Operation {
			return nil, false, fmt.Errorf("request_id 已用于其他命令")
		}
		var replay EnvironmentIncident
		if err := json.Unmarshal(previous.Response, &replay); err != nil {
			return nil, false, fmt.Errorf("解析幂等响应: %w", err)
		}
		return &replay, true, nil
	}
	if _, ok := s.state.Incidents[incident.IncidentID]; ok {
		return nil, false, ErrAlreadyExists
	}
	if _, ok := s.state.CaseNumbers[incident.CaseNumber]; ok {
		return nil, false, ErrAlreadyExists
	}
	contextKey := activeContextKey(incident.DisplayCaseID, incident.SensorID)
	if activeID := s.state.ActiveContexts[contextKey]; activeID != "" {
		active := s.state.Incidents[activeID]
		if active == nil || active.Status == StatusSealed {
			return nil, false, fmt.Errorf("在途上下文索引损坏")
		}
		return nil, false, &ActiveIncidentError{IncidentID: active.IncidentID, CaseNumber: active.CaseNumber, Status: active.Status, Revision: active.Revision}
	}
	next, err := cloneState(s.state)
	if err != nil {
		return nil, false, err
	}
	copyIncident, err := cloneIncident(incident)
	if err != nil {
		return nil, false, err
	}
	copyIncident.Revision = 1
	next.Incidents[copyIncident.IncidentID] = copyIncident
	next.CaseNumbers[copyIncident.CaseNumber] = copyIncident.IncidentID
	next.ActiveContexts[contextKey] = copyIncident.IncidentID
	if err := appendAuditAndCommand(&next, m, "", copyIncident.Status, copyIncident, s.now()); err != nil {
		return nil, false, err
	}
	if err := s.persist(next); err != nil {
		return nil, false, err
	}
	s.state = next
	result, err := cloneIncident(copyIncident)
	return result, false, err
}

func (s *Store) Update(m Mutation, mutate MutateFunc) (*EnvironmentIncident, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.state.Commands[commandKey(m.RequestID)]; ok {
		if previous.Operation != m.Operation || previous.IncidentID != m.IncidentID {
			return nil, false, fmt.Errorf("request_id 已用于其他命令")
		}
		var replay EnvironmentIncident
		if err := json.Unmarshal(previous.Response, &replay); err != nil {
			return nil, false, fmt.Errorf("解析幂等响应: %w", err)
		}
		return &replay, true, nil
	}
	current := s.state.Incidents[m.IncidentID]
	if current == nil {
		return nil, false, ErrNotFound
	}
	if current.Status == StatusSealed {
		return nil, false, ErrSealed
	}
	if current.Revision != m.ExpectedRevision {
		return nil, false, ErrRevisionConflict
	}
	next, err := cloneState(s.state)
	if err != nil {
		return nil, false, err
	}
	working := next.Incidents[m.IncidentID]
	from := working.Status
	oldContextKey := activeContextKey(working.DisplayCaseID, working.SensorID)
	if err := mutate(working); err != nil {
		return nil, false, err
	}
	newContextKey := activeContextKey(working.DisplayCaseID, working.SensorID)
	if working.Status != StatusSealed && newContextKey != oldContextKey {
		if activeID := next.ActiveContexts[newContextKey]; activeID != "" && activeID != working.IncidentID {
			active := next.Incidents[activeID]
			return nil, false, &ActiveIncidentError{IncidentID: active.IncidentID, CaseNumber: active.CaseNumber, Status: active.Status, Revision: active.Revision}
		}
		delete(next.ActiveContexts, oldContextKey)
		next.ActiveContexts[newContextKey] = working.IncidentID
	}
	working.Revision++
	if err := appendAuditAndCommand(&next, m, from, working.Status, working, s.now()); err != nil {
		return nil, false, err
	}
	if working.Status == StatusSealed {
		delete(next.ActiveContexts, activeContextKey(working.DisplayCaseID, working.SensorID))
	}
	if err := s.persist(next); err != nil {
		return nil, false, err
	}
	s.state = next
	result, err := cloneIncident(working)
	return result, false, err
}

func appendAuditAndCommand(state *persistedState, m Mutation, from, to Status, incident *EnvironmentIncident, occurredAt time.Time) error {
	payload, err := json.Marshal(m.Payload)
	if err != nil {
		return fmt.Errorf("序列化命令载荷: %w", err)
	}
	payloadHash := sha256.Sum256(payload)
	previous := ""
	if len(state.Audits) > 0 {
		previous = state.Audits[len(state.Audits)-1].EventDigest
	}
	event := AuditEvent{Sequence: int64(len(state.Audits) + 1), EventID: fmt.Sprintf("evt-%06d", len(state.Audits)+1), IncidentID: incident.IncidentID, EventType: m.EventType, FromStatus: from, ToStatus: to, ActorID: m.ActorID, RequestID: m.RequestID, PayloadDigest: hex.EncodeToString(payloadHash[:]), PreviousDigest: previous, OccurredAt: occurredAt}
	_ = json.Unmarshal(payload, &event.Details)
	enrichAuditDetails(&event, incident)
	canonicalDetails, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("序列化审计详情: %w", err)
	}
	if err := json.Unmarshal(canonicalDetails, &event.Details); err != nil {
		return fmt.Errorf("规范化审计详情: %w", err)
	}
	event.EventDigest = auditDigest(event)
	if event.EventType == "incident.sealed" && incident.ReopenDecision != nil {
		incident.ReopenDecision.EvidenceDigest = event.EventDigest
	}
	state.Audits = append(state.Audits, event)
	if event.EventType == "incident.sealed" {
		manifest, err := buildManifest(*state, incident, occurredAt)
		if err != nil {
			return err
		}
		incident.EvidenceManifest = manifest
	}
	response, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("序列化命令响应: %w", err)
	}
	state.Commands[commandKey(m.RequestID)] = CommandResult{RequestID: m.RequestID, IncidentID: incident.IncidentID, Operation: m.Operation, Response: response, CompletedAt: occurredAt}
	return nil
}

func enrichAuditDetails(event *AuditEvent, incident *EnvironmentIncident) {
	if event.Details == nil {
		event.Details = map[string]any{}
	}
	switch event.EventType {
	case "incident.reported":
		event.Details["discovery_reading_count"] = evidenceCounts(incident)["registration_readings"]
		event.Details["peak_reading_id"] = incident.PeakReadingID
		event.Details["risk_explanation"] = incident.RiskExplanation
	case "inspection.recorded":
		if value := incident.Inspection; value != nil {
			event.Details["risk_before"] = value.RiskBefore
			event.Details["risk_after"] = value.RiskAfter
			event.Details["temperature_difference"] = value.TemperatureDifference
			event.Details["humidity_difference"] = value.HumidityDifference
			event.Details["sensor_trustworthy"] = value.SensorTrustworthy
			event.Details["reassessment_reasons"] = value.ReassessmentReasons
			event.Details["hypotheses"] = value.Hypotheses
		}
	case "incident.readings_appended":
		event.Details["peak_reading_id"] = incident.PeakReadingID
		event.Details["risk_level"] = incident.RiskLevel
		event.Details["response_deadline"] = incident.ResponseDeadline
	case "inspection.hypothesis_validated":
		for _, hypothesis := range incident.Inspection.Hypotheses {
			if len(hypothesis.Conclusions) > 0 {
				latest := hypothesis.Conclusions[len(hypothesis.Conclusions)-1]
				if latest.RecordedBy == event.ActorID {
					event.Details["hypothesis_id"] = hypothesis.HypothesisID
					event.Details["conclusion_id"] = latest.ConclusionID
					event.Details["conclusion"] = latest.Conclusion
					event.Details["evidence_summary"] = latest.Evidence
				}
			}
		}
	case "deadline.acknowledged", "deadline.commitment_completed":
		if len(incident.DeadlineCommitments) > 0 {
			event.Details["commitment"] = incident.DeadlineCommitments[len(incident.DeadlineCommitments)-1]
			event.Details["original_response_deadline"] = incident.OriginalResponseDeadline
		}
	case "sensor.handed_over":
		if len(incident.SensorHandovers) > 0 {
			event.Details["sensor_handover"] = incident.SensorHandovers[len(incident.SensorHandovers)-1]
		}
	case "plan.submitted", "plan.approved", "plan.rejected":
		if value := incident.Plan; value != nil {
			event.Details["plan_version"] = value.Version
			event.Details["base_version"] = value.BaseVersion
			event.Details["review_status"] = value.ReviewStatus
			event.Details["correction_requirements"] = value.CorrectionRequirements
			event.Details["correction_resolutions"] = value.CorrectionResolutions
			event.Details["safety_envelope"] = value.SafetyEnvelope
			event.Details["safety_change_notes"] = value.SafetyChangeNotes
			event.Details["safety_frozen_at"] = value.SafetyFrozenAt
		}
	case "intervention.executed", "intervention.supplemented":
		if value := incident.Execution; value != nil {
			event.Details["execution_id"] = value.ExecutionID
			event.Details["plan_version"] = value.PlanVersion
			event.Details["supplemental"] = value.Supplemental
			event.Details["failed_verification_id"] = value.FailedVerificationID
			event.Details["calibration_difference"] = value.CalibrationDifference
		}
	case "execution.deviation_reviewed":
		if incident.Execution != nil {
			event.Details["execution_id"] = incident.Execution.ExecutionID
			event.Details["deviations"] = incident.Execution.Deviations
			event.Details["deviation_gate"] = incident.Execution.DeviationGate
		}
	case "recovery.observed":
		event.Details["observation_window"] = incident.CurrentObservationWindow
		event.Details["policy"] = incident.RecoveryPolicy
		event.Details["progress"] = incident.RecoveryProgress
	case "recovery.verified":
		if value := incident.Verification; value != nil {
			event.Details["verification_id"] = value.VerificationID
			event.Details["round"] = value.Round
			event.Details["observation_window"] = value.ObservationWindow
			event.Details["qualified"] = value.Qualified
			event.Details["failure_details"] = value.FailureDetails
		}
	case "reopen.held", "reopen.hold_requirement_resolved":
		if len(incident.ReopenHolds) > 0 {
			event.Details["reopen_hold"] = incident.ReopenHolds[len(incident.ReopenHolds)-1]
		}
	case "incident.sealed":
		event.Details["readiness_snapshot"] = incident.FinalReadinessSnapshot
		event.Details["reopen_holds"] = incident.ReopenHolds
	}
}

func auditDigest(event AuditEvent) string {
	material := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%s", event.Sequence, event.EventID, event.IncidentID, event.EventType, event.FromStatus, event.ToStatus, event.ActorID, event.RequestID, event.PayloadDigest, event.PreviousDigest)
	if len(event.Details) > 0 {
		details, _ := digestJSON(event.Details)
		material += "|" + details
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func digestJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func incidentEvidenceDigest(incident *EnvironmentIncident) (string, error) {
	copyIncident, err := cloneIncident(incident)
	if err != nil {
		return "", err
	}
	copyIncident.EvidenceManifest = nil
	return digestJSON(copyIncident)
}

func evidenceCounts(incident *EnvironmentIncident) map[string]int {
	counts := map[string]int{"registration_readings": 0, "inspections": 0, "hypotheses": 0, "hypothesis_conclusions": 0, "deadline_commitments": len(incident.DeadlineCommitments), "sensor_handovers": len(incident.SensorHandovers), "plan_versions": len(incident.PlanVersions), "plan_reviews": 0, "executions": len(incident.Executions), "execution_deviations": 0, "deviation_reviews": 0, "observation_windows": 0, "observation_readings": 0, "verifications": len(incident.Verifications), "reopen_holds": len(incident.ReopenHolds), "hold_resolutions": 0}
	if incident.Inspection != nil {
		counts["inspections"] = 1
		counts["hypotheses"] = len(incident.Inspection.Hypotheses)
		for _, hypothesis := range incident.Inspection.Hypotheses {
			counts["hypothesis_conclusions"] += len(hypothesis.Conclusions)
		}
	}
	windows := map[int]bool{}
	for _, reading := range incident.Readings {
		if reading.Phase == "detection" {
			counts["registration_readings"]++
		}
		if reading.Phase == "recovery" {
			counts["observation_readings"]++
			windows[reading.ObservationWindow] = true
		}
	}
	for _, plan := range incident.PlanVersions {
		if plan.ReviewStatus == "approved" || plan.ReviewStatus == "rejected" {
			counts["plan_reviews"]++
		}
	}
	for _, execution := range incident.Executions {
		counts["execution_deviations"] += len(execution.Deviations)
		for _, deviation := range execution.Deviations {
			counts["deviation_reviews"] += len(deviation.Reviews)
		}
	}
	for _, hold := range incident.ReopenHolds {
		for _, requirement := range hold.Requirements {
			if requirement.ResolvedAt != nil {
				counts["hold_resolutions"]++
			}
		}
	}
	counts["observation_windows"] = len(windows)
	return counts
}

func buildManifest(state persistedState, incident *EnvironmentIncident, at time.Time) (*EvidenceManifest, error) {
	manifest := &EvidenceManifest{IncidentID: incident.IncidentID, CaseNumber: incident.CaseNumber, CategoryCounts: evidenceCounts(incident), CreatedAt: at}
	var events []AuditEvent
	for _, event := range state.Audits {
		if event.IncidentID == incident.IncidentID {
			events = append(events, event)
		}
	}
	if len(events) > 0 {
		manifest.FirstAuditSequence = events[0].Sequence
		manifest.LastAuditSequence = events[len(events)-1].Sequence
		manifest.PreviousAnchor = events[0].PreviousDigest
		manifest.FinalAuditDigest = events[len(events)-1].EventDigest
	}
	digest, err := incidentEvidenceDigest(incident)
	if err != nil {
		return nil, err
	}
	manifest.IncidentDigest = digest
	material := *manifest
	material.ManifestDigest = ""
	manifest.ManifestDigest, err = digestJSON(material)
	return manifest, err
}

func verifyAuditChain(events []AuditEvent) error {
	previous := ""
	for i, event := range events {
		if event.Sequence != int64(i+1) {
			return fmt.Errorf("事件 %s 的序号不连续", event.EventID)
		}
		if event.PreviousDigest != previous {
			return fmt.Errorf("事件 %s 的前序摘要不匹配", event.EventID)
		}
		if event.EventDigest != auditDigest(event) {
			return fmt.Errorf("事件 %s 的摘要不匹配", event.EventID)
		}
		previous = event.EventDigest
	}
	return nil
}

func (s *Store) persist(next persistedState) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("创建数据目录: %w", err)
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化数据: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".microenv-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时数据文件: %w", err)
	}
	tempName := temp.Name()
	cleanup := func() { _ = temp.Close(); _ = os.Remove(tempName) }
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("设置数据文件权限: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("写入临时数据文件: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("同步临时数据文件: %w", err)
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("关闭临时数据文件: %w", err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("原子替换数据文件: %w", err)
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (s *Store) Get(incidentID string) (*EnvironmentIncident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	incident := s.state.Incidents[incidentID]
	if incident == nil {
		return nil, ErrNotFound
	}
	return cloneIncident(incident)
}

func (s *Store) List() ([]EnvironmentIncident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]EnvironmentIncident, 0, len(s.state.Incidents))
	for _, incident := range s.state.Incidents {
		copyIncident, err := cloneIncident(incident)
		if err != nil {
			return nil, err
		}
		items = append(items, *copyIncident)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].OpenedAt.After(items[j].OpenedAt) })
	return items, nil
}

func deadlineView(incident *EnvironmentIncident, now time.Time) (int64, DeadlineStatus) {
	remaining := int64(math.Ceil(incident.ResponseDeadline.Sub(now).Minutes()))
	if incident.Status == StatusSealed {
		return remaining, DeadlineArchived
	}
	if !incident.ResponseDeadline.After(now) {
		return remaining, DeadlineOverdue
	}
	if incident.ResponseDeadline.Sub(now) <= time.Hour {
		return remaining, DeadlineDueSoon
	}
	return remaining, DeadlineNormal
}

func effectiveCommitment(incident *EnvironmentIncident, now time.Time) *DeadlineCommitment {
	for i := len(incident.DeadlineCommitments) - 1; i >= 0; i-- {
		item := &incident.DeadlineCommitments[i]
		if item.InvalidatedAt == nil && item.CompletedAt == nil && item.CommitmentDueAt.After(now) {
			return item
		}
	}
	return nil
}

func escalationView(incident *EnvironmentIncident, now time.Time) EscalationStatus {
	if incident.Status == StatusSealed {
		return EscalationArchived
	}
	if !incident.ResponseDeadline.After(now) {
		if effectiveCommitment(incident, now) != nil {
			return EscalationOverdueAcknowledged
		}
		return EscalationOverdueUnacknowledged
	}
	if incident.ResponseDeadline.Sub(now) <= time.Hour {
		return EscalationDueSoon
	}
	return EscalationNormal
}

func containsStatus(values []Status, value Status) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func auditEvidenceGaps(incident *EnvironmentIncident, types map[string]bool) []string {
	expected := map[string]string{"incident.reported": "REGISTRATION_AUDIT_MISSING"}
	if incident.Inspection != nil {
		expected["inspection.recorded"] = "INSPECTION_AUDIT_MISSING"
	}
	if incident.Plan != nil && incident.Plan.ReviewStatus == "approved" {
		expected["plan.approved"] = "PLAN_REVIEW_AUDIT_MISSING"
	}
	if len(incident.Executions) > 0 {
		expected["intervention.executed"] = "EXECUTION_AUDIT_MISSING"
	}
	for _, reading := range incident.Readings {
		if reading.Phase == "recovery" {
			expected["recovery.observed"] = "OBSERVATION_AUDIT_MISSING"
			break
		}
	}
	if len(incident.Verifications) > 0 {
		expected["recovery.verified"] = "VERIFICATION_AUDIT_MISSING"
	}
	if incident.Status == StatusSealed {
		expected["incident.sealed"] = "SEAL_AUDIT_MISSING"
	}
	gaps := []string{}
	for eventType, code := range expected {
		if !types[eventType] {
			gaps = append(gaps, code)
		}
	}
	sort.Strings(gaps)
	return gaps
}

func mergeGaps(groups ...[]string) []string {
	seen := map[string]bool{}
	for _, group := range groups {
		for _, gap := range group {
			seen[gap] = true
		}
	}
	result := make([]string, 0, len(seen))
	for gap := range seen {
		result = append(result, gap)
	}
	sort.Strings(result)
	return result
}

func (s *Store) Query(query IncidentQuery) (IncidentPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cursorOpened, cursorID := "", ""
	if query.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(query.Cursor)
		if err != nil {
			return IncidentPage{}, fmt.Errorf("invalid cursor")
		}
		parts := strings.Split(string(raw), "|")
		switch len(parts) {
		case 3:
			snapshotAt, parseErr := time.Parse(time.RFC3339Nano, parts[0])
			if parseErr != nil {
				return IncidentPage{}, fmt.Errorf("invalid cursor")
			}
			query.Now, cursorOpened, cursorID = snapshotAt, parts[1], parts[2]
		case 2:
			cursorOpened, cursorID = parts[0], parts[1]
		case 1:
			cursorID = parts[0]
		default:
			return IncidentPage{}, fmt.Errorf("invalid cursor")
		}
	}
	if query.Stats {
		if err := verifyAuditChain(s.state.Audits); err != nil {
			return IncidentPage{}, fmt.Errorf("evidence integrity: %w", err)
		}
	}
	items := make([]IncidentListItem, 0)
	auditTypes := map[string]map[string]bool{}
	for _, event := range s.state.Audits {
		if auditTypes[event.IncidentID] == nil {
			auditTypes[event.IncidentID] = map[string]bool{}
		}
		auditTypes[event.IncidentID][event.EventType] = true
	}
	counts := map[DeadlineStatus]int{DeadlineNormal: 0, DeadlineDueSoon: 0, DeadlineOverdue: 0, DeadlineArchived: 0}
	escalationCounts := map[EscalationStatus]int{EscalationNormal: 0, EscalationDueSoon: 0, EscalationOverdueUnacknowledged: 0, EscalationOverdueAcknowledged: 0, EscalationArchived: 0}
	for _, incident := range s.state.Incidents {
		if len(query.Statuses) > 0 && !containsStatus(query.Statuses, incident.Status) {
			continue
		}
		if len(query.RiskLevels) > 0 && !containsString(query.RiskLevels, incident.RiskLevel) {
			continue
		}
		if query.DisplayCaseID != "" && normalizeIdentifier(incident.DisplayCaseID) != normalizeIdentifier(query.DisplayCaseID) {
			continue
		}
		if query.ArtifactID != "" && normalizeIdentifier(incident.ArtifactID) != normalizeIdentifier(query.ArtifactID) {
			continue
		}
		if query.SensorID != "" && normalizeIdentifier(incident.SensorID) != normalizeIdentifier(query.SensorID) {
			continue
		}
		if query.CaseNumber != "" && normalizeIdentifier(incident.CaseNumber) != normalizeIdentifier(query.CaseNumber) {
			continue
		}
		if !query.OpenedFrom.IsZero() && incident.OpenedAt.Before(query.OpenedFrom) {
			continue
		}
		if !query.OpenedTo.IsZero() && incident.OpenedAt.After(query.OpenedTo) {
			continue
		}
		copyIncident, err := cloneIncident(incident)
		if err != nil {
			return IncidentPage{}, err
		}
		remaining, deadlineStatus := deadlineView(copyIncident, query.Now)
		counts[deadlineStatus]++
		escalationStatus := escalationView(copyIncident, query.Now)
		escalationCounts[escalationStatus]++
		if query.DeadlineStatus != "" && query.DeadlineStatus != deadlineStatus {
			continue
		}
		if query.EscalationStatus != "" && query.EscalationStatus != escalationStatus {
			continue
		}
		owner := ""
		if commitment := effectiveCommitment(copyIncident, query.Now); commitment != nil {
			owner = commitment.OwnerID
		}
		if query.CommitmentOwnerID != "" && normalizeIdentifier(owner) != normalizeIdentifier(query.CommitmentOwnerID) {
			continue
		}
		gaps := mergeGaps(evidenceGaps(copyIncident), auditEvidenceGaps(copyIncident, auditTypes[copyIncident.IncidentID]))
		if query.EvidenceGap != "" && !containsString(gaps, query.EvidenceGap) {
			continue
		}
		items = append(items, IncidentListItem{EnvironmentIncident: *copyIncident, RemainingMinutes: remaining, DeadlineStatus: deadlineStatus, EscalationStatus: escalationStatus, CommitmentOwnerID: owner})
	}
	riskRank := func(level string) int {
		switch level {
		case "critical":
			return 4
		case "high":
			return 3
		case "moderate":
			return 2
		default:
			return 1
		}
	}
	deadlineRank := func(status DeadlineStatus) int {
		switch status {
		case DeadlineOverdue:
			return 0
		case DeadlineDueSoon:
			return 1
		case DeadlineNormal:
			return 2
		default:
			return 3
		}
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if deadlineRank(a.DeadlineStatus) != deadlineRank(b.DeadlineStatus) {
			return deadlineRank(a.DeadlineStatus) < deadlineRank(b.DeadlineStatus)
		}
		if riskRank(a.RiskLevel) != riskRank(b.RiskLevel) {
			return riskRank(a.RiskLevel) > riskRank(b.RiskLevel)
		}
		if !a.OpenedAt.Equal(b.OpenedAt) {
			return a.OpenedAt.Before(b.OpenedAt)
		}
		return a.IncidentID < b.IncidentID
	})
	start := 0
	if query.Cursor != "" {
		found := false
		for i := range items {
			if cursorOpened != "" {
				if items[i].IncidentID == cursorID && items[i].OpenedAt.Format(time.RFC3339Nano) == cursorOpened {
					start = i + 1
					found = true
					break
				}
			} else if items[i].IncidentID == cursorID {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return IncidentPage{}, fmt.Errorf("invalid cursor")
		}
	}
	end := start + query.Limit
	if end > len(items) {
		end = len(items)
	}
	page := IncidentPage{Items: items[start:end], DeadlineCounts: counts, EscalationCounts: escalationCounts}
	if query.Stats {
		stats := &IncidentStats{GeneratedAt: query.Now, IncidentCount: len(items), EvidenceGapCounts: map[string]int{}, ByDisplayCase: map[string]int{}, ByRiskLevel: map[string]int{}, ByStatus: map[Status]int{}}
		var handlingMinutes float64
		for i := range items {
			item := &items[i]
			stats.ByDisplayCase[item.DisplayCaseID]++
			stats.ByRiskLevel[item.RiskLevel]++
			stats.ByStatus[item.Status]++
			if item.DeadlineStatus == DeadlineOverdue {
				stats.OverdueCount++
			}
			endAt := query.Now
			gaps := mergeGaps(evidenceGaps(&item.EnvironmentIncident), auditEvidenceGaps(&item.EnvironmentIncident, auditTypes[item.IncidentID]))
			if item.SealedAt != nil && len(gaps) == 0 {
				stats.SealedCount++
				endAt = *item.SealedAt
			}
			handlingMinutes += endAt.Sub(item.OpenedAt).Minutes()
			if len(gaps) > 0 {
				stats.EvidenceGapIncidentIDs = append(stats.EvidenceGapIncidentIDs, item.IncidentID)
				stats.EvidenceGapIncidentCaseNumbers = append(stats.EvidenceGapIncidentCaseNumbers, item.CaseNumber)
				for _, gap := range gaps {
					stats.EvidenceGapCounts[gap]++
				}
			}
		}
		if stats.IncidentCount > 0 {
			stats.SealedRate = float64(stats.SealedCount) / float64(stats.IncidentCount)
			stats.AverageHandlingMinutes = handlingMinutes / float64(stats.IncidentCount)
		}
		sort.Strings(stats.EvidenceGapIncidentIDs)
		sort.Strings(stats.EvidenceGapIncidentCaseNumbers)
		page.Stats = stats
	}
	if end < len(items) && end > start {
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(query.Now.Format(time.RFC3339Nano) + "|" + items[end-1].OpenedAt.Format(time.RFC3339Nano) + "|" + items[end-1].IncidentID))
	}
	return page, nil
}

func (s *Store) Timeline(incidentID string) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.Incidents[incidentID] == nil {
		return nil, ErrNotFound
	}
	if err := verifyAuditChain(s.state.Audits); err != nil {
		return nil, fmt.Errorf("evidence integrity: %w", err)
	}
	events := make([]AuditEvent, 0)
	for _, event := range s.state.Audits {
		if event.IncidentID == incidentID {
			events = append(events, event)
		}
	}
	data, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	var result []AuditEvent
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) Evidence(incidentID string) (EvidenceSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	incident := s.state.Incidents[incidentID]
	if incident == nil {
		return EvidenceSummary{}, ErrNotFound
	}
	summary := EvidenceSummary{IncidentID: incidentID, Sealed: incident.Status == StatusSealed, SealedAt: incident.SealedAt, Status: "unsealed"}
	for _, event := range s.state.Audits {
		if event.IncidentID == incidentID {
			summary.EventCount++
			summary.LatestDigest = event.EventDigest
		}
	}
	if incident.Status != StatusSealed || incident.EvidenceManifest == nil {
		summary.Reasons = []string{"事件尚未封存"}
		summary.EvidenceGaps = evidenceGaps(incident)
		return summary, nil
	}
	if err := verifyAuditChain(s.state.Audits); err != nil {
		return EvidenceSummary{}, fmt.Errorf("evidence integrity: %w", err)
	}
	digest, err := incidentEvidenceDigest(incident)
	if err != nil {
		return EvidenceSummary{}, err
	}
	manifestMaterial := *incident.EvidenceManifest
	storedManifestDigest := manifestMaterial.ManifestDigest
	manifestMaterial.ManifestDigest = ""
	calculatedManifestDigest, err := digestJSON(manifestMaterial)
	if err != nil {
		return EvidenceSummary{}, err
	}
	if digest != incident.EvidenceManifest.IncidentDigest {
		return EvidenceSummary{}, fmt.Errorf("evidence integrity: 事件摘要不匹配")
	}
	if calculatedManifestDigest != storedManifestDigest {
		return EvidenceSummary{}, fmt.Errorf("evidence integrity: 封存清单摘要不匹配")
	}
	if summary.LatestDigest != incident.EvidenceManifest.FinalAuditDigest {
		return EvidenceSummary{}, fmt.Errorf("evidence integrity: 最终审计摘要不匹配")
	}
	summary.Status = "complete"
	summary.EvidenceGaps = evidenceGaps(incident)
	manifestCopy := *incident.EvidenceManifest
	summary.Manifest = &manifestCopy
	return summary, nil
}

func evidenceGaps(incident *EnvironmentIncident) []string {
	counts := evidenceCounts(incident)
	gaps := []string{}
	for key, code := range map[string]string{"registration_readings": "REGISTRATION_MISSING", "inspections": "INSPECTION_MISSING", "plan_reviews": "PLAN_REVIEW_MISSING", "executions": "EXECUTION_MISSING", "observation_readings": "OBSERVATION_MISSING", "verifications": "VERIFICATION_MISSING"} {
		if counts[key] == 0 {
			gaps = append(gaps, code)
		}
	}
	sort.Strings(gaps)
	return gaps
}

func cloneState(state persistedState) (persistedState, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return persistedState{}, err
	}
	var result persistedState
	if err := json.Unmarshal(data, &result); err != nil {
		return persistedState{}, err
	}
	return result, nil
}

func cloneIncident(incident *EnvironmentIncident) (*EnvironmentIncident, error) {
	data, err := json.Marshal(incident)
	if err != nil {
		return nil, err
	}
	var result EnvironmentIncident
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
