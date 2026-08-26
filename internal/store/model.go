package store

import "time"

type Status string

const (
	StatusReported       Status = "reported"
	StatusInspected      Status = "inspected"
	StatusPlanSubmitted  Status = "plan_submitted"
	StatusPlanApproved   Status = "plan_approved"
	StatusExecuted       Status = "executed"
	StatusObserving      Status = "observing"
	StatusRecoveryPassed Status = "recovery_passed"
	StatusSealed         Status = "sealed"
)

type Range struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

type EnvironmentReading struct {
	ReadingID               string     `json:"reading_id"`
	IncidentID              string     `json:"incident_id"`
	CapturedAt              time.Time  `json:"captured_at"`
	TemperatureCelsius      float64    `json:"temperature_celsius"`
	RelativeHumidityPercent float64    `json:"relative_humidity_percent"`
	SensorStatus            string     `json:"sensor_status"`
	CalibrationReference    string     `json:"calibration_reference,omitempty"`
	OperatorID              string     `json:"operator_id"`
	Phase                   string     `json:"phase"`
	ObservationWindow       int        `json:"observation_window,omitempty"`
	ObservationSegment      int        `json:"observation_segment,omitempty"`
	EligibleForRecovery     bool       `json:"eligible_for_recovery,omitempty"`
	ExclusionReason         string     `json:"exclusion_reason,omitempty"`
	QualityNote             string     `json:"quality_note,omitempty"`
	QualityFlag             string     `json:"quality_flag,omitempty"`
	QualityScore            int        `json:"quality_score,omitempty"`
	SensorID                string     `json:"sensor_id,omitempty"`
	ReviewStatus            string     `json:"review_status,omitempty"`
	ReviewConclusion        string     `json:"review_conclusion,omitempty"`
	ReviewedBy              string     `json:"reviewed_by,omitempty"`
	ReviewedAt              *time.Time `json:"reviewed_at,omitempty"`
}

type ContextSnapshot struct {
	Version              int       `json:"version"`
	DisplayCaseID        string    `json:"display_case_id"`
	ArtifactID           string    `json:"artifact_id"`
	SensorID             string    `json:"sensor_id"`
	CalibrationReference string    `json:"calibration_reference,omitempty"`
	Validated            bool      `json:"validated"`
	ValidationResult     string    `json:"validation_result"`
	OriginalIncidentID   string    `json:"original_incident_id,omitempty"`
	ChangeReason         string    `json:"change_reason,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

type ReassessmentTask struct {
	TaskID           string     `json:"task_id"`
	IncidentID       string     `json:"incident_id"`
	DueAt            time.Time  `json:"due_at"`
	Status           string     `json:"status"`
	OwnerID          string     `json:"owner_id,omitempty"`
	RemainingMinutes int64      `json:"remaining_minutes"`
	EscalationReason string     `json:"escalation_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ConfirmedAt      *time.Time `json:"confirmed_at,omitempty"`
}

type RecoverySamplingPlan struct {
	Version           int       `json:"version"`
	Window            int       `json:"window"`
	MinimumInterval   int64     `json:"minimum_interval_minutes"`
	MaximumInterval   int64     `json:"maximum_interval_minutes"`
	NextDueAt         time.Time `json:"next_due_at"`
	SampledReadingIDs []string  `json:"sampled_reading_ids,omitempty"`
}

type RiskEvaluation struct {
	Sequence             int       `json:"sequence"`
	EvaluatedAt          time.Time `json:"evaluated_at"`
	RiskLevel            string    `json:"risk_level"`
	RiskScore            int       `json:"risk_score"`
	Reasons              []string  `json:"reasons"`
	ResponseDeadline     time.Time `json:"response_deadline"`
	PeakReadingID        string    `json:"peak_reading_id,omitempty"`
	Explanation          string    `json:"explanation,omitempty"`
	PreviousRiskLevel    string    `json:"previous_risk_level,omitempty"`
	PreviousRiskScore    int       `json:"previous_risk_score,omitempty"`
	LevelDelta           int       `json:"level_delta,omitempty"`
	ScoreDelta           int       `json:"score_delta,omitempty"`
	DeadlineDeltaMinutes int64     `json:"deadline_delta_minutes,omitempty"`
	TrendSlope           float64   `json:"trend_slope,omitempty"`
	DurationMinutes      int64     `json:"duration_minutes,omitempty"`
	EscalationReason     string    `json:"escalation_reason,omitempty"`
}

type CauseConclusion struct {
	ConclusionID         string    `json:"conclusion_id"`
	HypothesisID         string    `json:"hypothesis_id"`
	Conclusion           string    `json:"conclusion"`
	VerificationMethod   string    `json:"verification_method"`
	Evidence             string    `json:"evidence"`
	PreviousConclusionID string    `json:"previous_conclusion_id,omitempty"`
	RecordedBy           string    `json:"recorded_by"`
	RecordedAt           time.Time `json:"recorded_at"`
}

type CauseHypothesis struct {
	HypothesisID      string            `json:"hypothesis_id"`
	Description       string            `json:"description"`
	CreatedBy         string            `json:"created_by"`
	CreatedAt         time.Time         `json:"created_at"`
	Conclusions       []CauseConclusion `json:"conclusions"`
	CurrentConclusion string            `json:"current_conclusion"`
}

type Inspection struct {
	CheckedAt                    time.Time            `json:"checked_at"`
	InspectorID                  string               `json:"inspector_id"`
	Finding                      string               `json:"finding"`
	CauseHypotheses              []string             `json:"cause_hypotheses"`
	IsolationMeasure             string               `json:"isolation_measure,omitempty"`
	IndependentReading           EnvironmentReading   `json:"independent_reading"`
	AlternativeMonitoring        string               `json:"alternative_monitoring,omitempty"`
	TemperatureDifference        float64              `json:"temperature_difference"`
	HumidityDifference           float64              `json:"humidity_difference"`
	SensorTrustworthy            bool                 `json:"sensor_trustworthy"`
	RiskBefore                   string               `json:"risk_before"`
	RiskAfter                    string               `json:"risk_after"`
	ReassessmentReasons          []string             `json:"reassessment_reasons"`
	Hypotheses                   []CauseHypothesis    `json:"hypotheses,omitempty"`
	AlternativeReviewAt          *time.Time           `json:"alternative_review_at,omitempty"`
	IndependentReadings          []EnvironmentReading `json:"independent_readings,omitempty"`
	MedianTemperatureDifference  float64              `json:"median_temperature_difference,omitempty"`
	MedianHumidityDifference     float64              `json:"median_humidity_difference,omitempty"`
	MaximumTemperatureDifference float64              `json:"maximum_temperature_difference,omitempty"`
	MaximumHumidityDifference    float64              `json:"maximum_humidity_difference,omitempty"`
	ReportConclusion             string               `json:"report_conclusion,omitempty"`
	ReportGaps                   []string             `json:"report_gaps,omitempty"`
}

type SafetyEnvelope struct {
	MaxTemperatureChangePerHour float64  `json:"max_temperature_change_per_hour"`
	MaxHumidityChangePerHour    float64  `json:"max_humidity_change_per_hour"`
	MaxExposureMinutes          int64    `json:"max_exposure_minutes"`
	StopTemperature             Range    `json:"stop_temperature_range"`
	StopHumidity                Range    `json:"stop_humidity_range"`
	RollbackSteps               []string `json:"rollback_steps"`
	RollbackOwnerID             string   `json:"rollback_owner_id"`
}

type CorrectionRequirement struct {
	RequirementID    string     `json:"requirement_id"`
	Description      string     `json:"description"`
	ResponsibleStep  string     `json:"responsible_step,omitempty"`
	RiskExplanation  string     `json:"risk_explanation,omitempty"`
	EvidenceRequired string     `json:"evidence_required,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
}

type CorrectionResolution struct {
	RequirementID string `json:"requirement_id"`
	Resolution    string `json:"resolution"`
	Resolved      bool   `json:"resolved"`
	Evidence      string `json:"evidence,omitempty"`
}

type InterventionPlan struct {
	PlanID                 string                  `json:"plan_id"`
	IncidentID             string                  `json:"incident_id"`
	Steps                  []string                `json:"steps"`
	TargetTemperatureRange Range                   `json:"target_temperature_range"`
	TargetHumidityRange    Range                   `json:"target_humidity_range"`
	IsolationRequired      bool                    `json:"isolation_required"`
	SubmittedBy            string                  `json:"submitted_by"`
	SubmittedAt            time.Time               `json:"submitted_at"`
	ReviewerID             string                  `json:"reviewer_id,omitempty"`
	ReviewStatus           string                  `json:"review_status"`
	ReviewNote             string                  `json:"review_note,omitempty"`
	ReviewedAt             *time.Time              `json:"reviewed_at,omitempty"`
	ExecutedAt             *time.Time              `json:"executed_at,omitempty"`
	Version                int                     `json:"version"`
	BaseVersion            int                     `json:"base_version,omitempty"`
	CorrectionRequirements []CorrectionRequirement `json:"correction_requirements,omitempty"`
	CorrectionResolutions  []CorrectionResolution  `json:"correction_resolutions,omitempty"`
	SafetyEnvelope         *SafetyEnvelope         `json:"safety_envelope,omitempty"`
	SafetyChangeNotes      map[string]string       `json:"safety_change_notes,omitempty"`
	SafetyFrozenAt         *time.Time              `json:"safety_frozen_at,omitempty"`
	SafetyReviewSummary    string                  `json:"safety_review_summary,omitempty"`
	PreflightVersion       int                     `json:"preflight_version,omitempty"`
	PreflightPassed        bool                    `json:"preflight_passed,omitempty"`
	PreflightSummary       string                  `json:"preflight_summary,omitempty"`
}

type MaterialUsage struct {
	Name        string    `json:"name"`
	BatchNumber string    `json:"batch_number"`
	Quantity    any       `json:"quantity"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type StepExecutionResult struct {
	StepNumber      int    `json:"step_number"`
	Step            string `json:"step,omitempty"`
	Result          string `json:"result"`
	DeviationReason string `json:"deviation_reason,omitempty"`
	SafetyCritical  bool   `json:"safety_critical"`
}

type CalibrationDifference struct {
	Temperature float64 `json:"temperature"`
	Humidity    float64 `json:"humidity"`
}

type Execution struct {
	ExecutedAt             time.Time             `json:"executed_at"`
	OperatorID             string                `json:"operator_id"`
	Notes                  string                `json:"notes"`
	Materials              []MaterialUsage       `json:"materials"`
	CalibrationBefore      EnvironmentReading    `json:"calibration_before"`
	CalibrationAfter       EnvironmentReading    `json:"calibration_after"`
	ExecutionID            string                `json:"execution_id"`
	PlanVersion            int                   `json:"plan_version"`
	StepResults            []StepExecutionResult `json:"step_results"`
	CalibrationDifference  CalibrationDifference `json:"calibration_difference"`
	Supplemental           bool                  `json:"supplemental"`
	FailedVerificationID   string                `json:"failed_verification_id,omitempty"`
	ResolvesDeviationID    string                `json:"resolves_deviation_id,omitempty"`
	DurationMinutes        int64                 `json:"duration_minutes,omitempty"`
	Deviations             []ExecutionDeviation  `json:"deviations,omitempty"`
	DeviationGate          string                `json:"deviation_gate,omitempty"`
	CalibrationDrift       bool                  `json:"calibration_drift,omitempty"`
	CalibrationDriftReason string                `json:"calibration_drift_reason,omitempty"`
}

type ExecutionDeviation struct {
	DeviationID      string            `json:"deviation_id"`
	Type             string            `json:"type"`
	Reason           string            `json:"reason"`
	ImmediateControl string            `json:"immediate_control"`
	PlanStepNumber   int               `json:"plan_step_number"`
	Classification   string            `json:"classification"`
	RecordedBy       string            `json:"recorded_by"`
	RecordedAt       time.Time         `json:"recorded_at"`
	Reviews          []DeviationReview `json:"reviews,omitempty"`
	CurrentDecision  string            `json:"current_decision"`
}

type DeviationReview struct {
	ReviewID        string    `json:"review_id"`
	Decision        string    `json:"decision"`
	RiskExplanation string    `json:"risk_explanation"`
	ReviewerID      string    `json:"reviewer_id"`
	ReviewedAt      time.Time `json:"reviewed_at"`
}

type DeadlineCommitment struct {
	CommitmentID    string     `json:"commitment_id"`
	Stage           string     `json:"stage"`
	Reason          string     `json:"reason"`
	OwnerID         string     `json:"owner_id"`
	NextAction      string     `json:"next_action"`
	CommittedAt     time.Time  `json:"committed_at"`
	CommitmentDueAt time.Time  `json:"commitment_due_at"`
	InvalidatedAt   *time.Time `json:"invalidated_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	ConfirmedBy     string     `json:"confirmed_by"`
	Status          string     `json:"status"`
}

type SensorHandover struct {
	HandoverID   string               `json:"handover_id"`
	OldSensorID  string               `json:"old_sensor_id"`
	NewSensorID  string               `json:"new_sensor_id"`
	RemovedAt    time.Time            `json:"removed_at"`
	InstalledAt  time.Time            `json:"installed_at"`
	HandedOverBy string               `json:"handed_over_by"`
	Reason       string               `json:"reason"`
	Reference    string               `json:"calibration_reference"`
	OldReadings  []EnvironmentReading `json:"old_sensor_readings"`
	NewReadings  []EnvironmentReading `json:"new_sensor_readings"`
	CompletedAt  time.Time            `json:"completed_at"`
}

type RecoveryPolicySnapshot struct {
	Version              string    `json:"version"`
	MinimumStableMinutes int64     `json:"minimum_stable_minutes"`
	MinimumReadings      int       `json:"minimum_readings"`
	MaximumGapMinutes    int64     `json:"maximum_gap_minutes"`
	GeneratedAt          time.Time `json:"generated_at"`
}

type RecoveryProgressSummary struct {
	PolicyVersion          string     `json:"policy_version"`
	StableMinutes          int64      `json:"stable_minutes"`
	ValidReadings          int        `json:"valid_readings"`
	RemainingMinutes       int64      `json:"remaining_minutes"`
	RemainingReadings      int        `json:"remaining_readings"`
	LatestInterruption     string     `json:"latest_interruption,omitempty"`
	EarliestVerificationAt *time.Time `json:"earliest_verification_at,omitempty"`
	Qualified              bool       `json:"qualified"`
}

type HoldRequirement struct {
	RequirementID string     `json:"requirement_id"`
	Description   string     `json:"description"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
	Resolution    string     `json:"resolution,omitempty"`
	EvidenceRef   string     `json:"evidence_ref,omitempty"`
	ResolvedBy    string     `json:"resolved_by,omitempty"`
}

type ReopenHold struct {
	HoldID       string            `json:"hold_id"`
	ReasonCode   string            `json:"reason_code"`
	Requirements []HoldRequirement `json:"requirements"`
	ReviewDueAt  time.Time         `json:"review_due_at"`
	DecidedBy    string            `json:"decided_by"`
	DecidedAt    time.Time         `json:"decided_at"`
	Status       string            `json:"status"`
}

type ReadinessCheck struct {
	Code    string `json:"code"`
	Ready   bool   `json:"ready"`
	Message string `json:"message"`
}

type ReadinessSnapshot struct {
	CheckedAt         time.Time        `json:"checked_at"`
	Ready             bool             `json:"ready"`
	Checks            []ReadinessCheck `json:"checks"`
	Revision          int64            `json:"revision"`
	RiskLevel         string           `json:"risk_level"`
	ObservationWindow int              `json:"observation_window"`
	AuditTailDigest   string           `json:"audit_tail_digest"`
}

type VerificationFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RecoveryVerification struct {
	VerifiedAt                    time.Time             `json:"verified_at"`
	VerifiedBy                    string                `json:"verified_by"`
	Qualified                     bool                  `json:"qualified"`
	StableMinutes                 int64                 `json:"stable_minutes"`
	Failures                      []string              `json:"failures"`
	VerificationID                string                `json:"verification_id"`
	Round                         int                   `json:"round"`
	ObservationWindow             int                   `json:"observation_window"`
	FailureDetails                []VerificationFailure `json:"failure_details,omitempty"`
	NeedsSupplementalIntervention bool                  `json:"needs_supplemental_intervention"`
}

type ReopenDecision struct {
	SignedAt       time.Time `json:"signed_at"`
	SupervisorID   string    `json:"supervisor_id"`
	Decision       string    `json:"decision"`
	Note           string    `json:"note"`
	EvidenceDigest string    `json:"evidence_digest"`
}

type EvidenceManifest struct {
	IncidentID         string         `json:"incident_id"`
	CaseNumber         string         `json:"case_number"`
	CategoryCounts     map[string]int `json:"category_counts"`
	FirstAuditSequence int64          `json:"first_audit_sequence"`
	LastAuditSequence  int64          `json:"last_audit_sequence"`
	PreviousAnchor     string         `json:"previous_anchor,omitempty"`
	FinalAuditDigest   string         `json:"final_audit_digest"`
	IncidentDigest     string         `json:"incident_digest"`
	ManifestDigest     string         `json:"manifest_digest"`
	CreatedAt          time.Time      `json:"created_at"`
}

type EnvironmentIncident struct {
	IncidentID                     string                   `json:"incident_id"`
	CaseNumber                     string                   `json:"case_number"`
	DisplayCaseID                  string                   `json:"display_case_id"`
	ArtifactID                     string                   `json:"artifact_id"`
	SensorID                       string                   `json:"sensor_id"`
	CalibrationReference           string                   `json:"calibration_reference,omitempty"`
	CalibrationExpiresAt           *time.Time               `json:"calibration_expires_at,omitempty"`
	BaselineVersion                string                   `json:"baseline_version,omitempty"`
	OpenedAt                       time.Time                `json:"opened_at"`
	AbnormalSince                  time.Time                `json:"abnormal_since"`
	Sensitivity                    string                   `json:"sensitivity"`
	BaselineTemperature            Range                    `json:"baseline_temperature"`
	BaselineHumidity               Range                    `json:"baseline_humidity"`
	RiskLevel                      string                   `json:"risk_level"`
	RiskScore                      int                      `json:"risk_score"`
	RiskReasons                    []string                 `json:"risk_reasons"`
	InitialRiskEvaluation          RiskEvaluation           `json:"initial_risk_evaluation"`
	RiskEvaluations                []RiskEvaluation         `json:"risk_evaluations,omitempty"`
	ResponseDeadline               time.Time                `json:"response_deadline"`
	OriginalResponseDeadline       time.Time                `json:"original_response_deadline"`
	Status                         Status                   `json:"status"`
	Revision                       int64                    `json:"revision"`
	CreatedBy                      string                   `json:"created_by"`
	SealedAt                       *time.Time               `json:"sealed_at,omitempty"`
	Inspection                     *Inspection              `json:"inspection,omitempty"`
	Plan                           *InterventionPlan        `json:"plan,omitempty"`
	PlanVersions                   []InterventionPlan       `json:"plan_versions,omitempty"`
	Execution                      *Execution               `json:"execution,omitempty"`
	Executions                     []Execution              `json:"executions,omitempty"`
	Verification                   *RecoveryVerification    `json:"verification,omitempty"`
	Verifications                  []RecoveryVerification   `json:"verifications,omitempty"`
	CurrentObservationWindow       int                      `json:"current_observation_window,omitempty"`
	LatestObservationInterruption  string                   `json:"latest_observation_interruption,omitempty"`
	LatestObservationInterruptedAt *time.Time               `json:"latest_observation_interrupted_at,omitempty"`
	ReopenDecision                 *ReopenDecision          `json:"reopen_decision,omitempty"`
	EvidenceManifest               *EvidenceManifest        `json:"evidence_manifest,omitempty"`
	Readings                       []EnvironmentReading     `json:"readings"`
	PeakReadingID                  string                   `json:"peak_reading_id,omitempty"`
	RiskExplanation                string                   `json:"risk_explanation,omitempty"`
	DeadlineCommitments            []DeadlineCommitment     `json:"deadline_commitments,omitempty"`
	SensorHandovers                []SensorHandover         `json:"sensor_handovers,omitempty"`
	RecoveryPolicy                 *RecoveryPolicySnapshot  `json:"recovery_policy,omitempty"`
	RecoveryProgress               *RecoveryProgressSummary `json:"recovery_progress,omitempty"`
	ReopenHolds                    []ReopenHold             `json:"reopen_holds,omitempty"`
	FinalReadinessSnapshot         *ReadinessSnapshot       `json:"final_readiness_snapshot,omitempty"`
	EscalationStatus               EscalationStatus         `json:"escalation_status,omitempty"`
	RemainingMinutes               int64                    `json:"remaining_minutes,omitempty"`
	CommitmentOwnerID              string                   `json:"commitment_owner_id,omitempty"`
	ContextSnapshots               []ContextSnapshot        `json:"context_snapshots,omitempty"`
	CurrentContextVersion          int                      `json:"current_context_version,omitempty"`
	ReassessmentTasks              []ReassessmentTask       `json:"reassessment_tasks,omitempty"`
	RecoverySamplingPlan           *RecoverySamplingPlan    `json:"recovery_sampling_plan,omitempty"`
}

type AuditEvent struct {
	Sequence       int64          `json:"sequence"`
	EventID        string         `json:"event_id"`
	IncidentID     string         `json:"incident_id"`
	EventType      string         `json:"event_type"`
	FromStatus     Status         `json:"from_status,omitempty"`
	ToStatus       Status         `json:"to_status"`
	ActorID        string         `json:"actor_id"`
	RequestID      string         `json:"request_id"`
	PayloadDigest  string         `json:"payload_digest"`
	PreviousDigest string         `json:"previous_digest,omitempty"`
	EventDigest    string         `json:"event_digest"`
	OccurredAt     time.Time      `json:"occurred_at"`
	Details        map[string]any `json:"details,omitempty"`
}

type CommandResult struct {
	RequestID     string    `json:"request_id"`
	IncidentID    string    `json:"incident_id"`
	Operation     string    `json:"operation"`
	PayloadDigest string    `json:"payload_digest,omitempty"`
	Response      []byte    `json:"response"`
	CompletedAt   time.Time `json:"completed_at"`
}

type EvidenceSummary struct {
	IncidentID   string            `json:"incident_id"`
	EventCount   int               `json:"event_count"`
	LatestDigest string            `json:"latest_digest"`
	Sealed       bool              `json:"sealed"`
	SealedAt     *time.Time        `json:"sealed_at,omitempty"`
	Status       string            `json:"status"`
	Reasons      []string          `json:"reasons,omitempty"`
	EvidenceGaps []string          `json:"evidence_gaps,omitempty"`
	Manifest     *EvidenceManifest `json:"manifest,omitempty"`
}

type DeadlineStatus string

const (
	DeadlineNormal   DeadlineStatus = "normal"
	DeadlineDueSoon  DeadlineStatus = "due_soon"
	DeadlineOverdue  DeadlineStatus = "overdue"
	DeadlineArchived DeadlineStatus = "archived"
)

type EscalationStatus string

const (
	EscalationNormal                EscalationStatus = "normal"
	EscalationDueSoon               EscalationStatus = "due_soon"
	EscalationOverdueUnacknowledged EscalationStatus = "overdue_unacknowledged"
	EscalationOverdueAcknowledged   EscalationStatus = "overdue_acknowledged"
	EscalationArchived              EscalationStatus = "archived"
)

type IncidentListItem struct {
	EnvironmentIncident
	RemainingMinutes  int64            `json:"remaining_minutes"`
	DeadlineStatus    DeadlineStatus   `json:"deadline_status"`
	EscalationStatus  EscalationStatus `json:"escalation_status"`
	CommitmentOwnerID string           `json:"commitment_owner_id,omitempty"`
}
