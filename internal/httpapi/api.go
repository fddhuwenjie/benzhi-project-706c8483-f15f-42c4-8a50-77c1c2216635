package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

type API struct {
	service   *cases.Service
	startedAt time.Time
}

func New(service *cases.Service) *API { return &API{service: service, startedAt: time.Now().UTC()} }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.Health)
	mux.HandleFunc("GET /internal/self-check", a.SelfCheck)
	mux.HandleFunc("GET /v1/environment-incidents", a.ListIncidents)
	mux.HandleFunc("POST /v1/environment-incidents", a.CreateIncident)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}", a.GetIncident)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/discovery-readings", a.AppendDiscoveryReadings)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/readings", a.AppendDiscoveryReadings)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/readings/{readingID}/review", a.ReviewReading)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/context-snapshots", a.GetContextSnapshots)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/reassessment-tasks", a.GetReassessmentTasks)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/inspection", a.RecordInspection)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/inspection/hypotheses/{hypothesisID}/validations", a.ValidateHypothesis)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/deadline-acknowledgements", a.AcknowledgeDeadline)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/deadline-commitments/{commitmentID}/complete", a.CompleteDeadlineCommitment)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/sensor-handover", a.HandoverSensor)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/plans", a.SubmitPlan)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/plans/diff", a.GetPlanDiff)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/plan-review", a.ReviewPlan)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/execution", a.RecordExecution)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/materials", a.GetMaterials)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/material-tracking", a.GetMaterials)
	mux.HandleFunc("GET /v1/material-tracking", a.GetMaterialTracking)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/executions/{executionID}/deviations/{deviationID}/review", a.ReviewDeviation)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/observations", a.AddObservations)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/recovery-progress", a.GetRecoveryProgress)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/verification-history", a.GetVerificationHistory)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/verifications", a.GetVerificationHistory)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/verification", a.VerifyRecovery)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/reopen-readiness", a.GetReopenReadiness)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/reopen-holds", a.PlaceReopenHold)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/reopen-holds/{holdID}/requirements/{requirementID}/resolve", a.ResolveHoldRequirement)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/reopen-holds/{holdID}/renew", a.RenewReopenHold)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/reopen-signature", a.SignReopen)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/timeline", a.GetTimeline)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/inspection-report", a.GetInspectionReport)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/inspection/trust-report", a.GetInspectionReport)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/evidence", a.GetEvidence)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/risk-history", a.GetRiskHistory)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/inspection/follow-ups", a.GetFollowUps)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/plans/preflight", a.PlanPreflight)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/execution-summary", a.GetExecutionSummary)
	mux.HandleFunc("GET /v1/environment-incidents/{incidentID}/reopen-preview", a.GetReopenPreview)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/deadline-commitments/{commitmentID}/expire", a.ExpireCommitment)
	mux.HandleFunc("POST /v1/environment-incidents/{incidentID}/deadline-commitments/{commitmentID}/renew", a.RenewCommitment)
	return requestMiddleware(mux)
}

type errorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type responseEnvelope struct {
	Data any            `json:"data"`
	Meta map[string]any `json:"meta,omitempty"`
}

func (a *API) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, responseEnvelope{Data: map[string]any{"status": "ok", "service": "展柜微环境异常复原台", "started_at": a.startedAt}})
}

func (a *API) SelfCheck(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		writeAPIError(w, r, http.StatusForbidden, "SELF_CHECK_FORBIDDEN", "自检路由仅允许回环客户端访问")
		return
	}
	incidents, err := a.service.List()
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: map[string]any{"status": "ok", "persistence_readable": true, "incident_count": len(incidents)}})
}

func (a *API) CreateIncident(w http.ResponseWriter, r *http.Request) {
	var input cases.CreateIncidentInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	if len(input.DiscoveryReadings) > 100 {
		writeAPIError(w, r, http.StatusBadRequest, "BATCH_TOO_LARGE", "发现阶段读数批次不能超过 100 条")
		return
	}
	incident, replayed, err := a.service.CreateIncident(input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusCreated, incident, replayed)
}

func (a *API) RecordInspection(w http.ResponseWriter, r *http.Request) {
	var input cases.InspectionInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.RecordInspectionContext(r.Context(), r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) AppendDiscoveryReadings(w http.ResponseWriter, r *http.Request) {
	var input cases.AppendDiscoveryReadingsInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.AppendDiscoveryReadings(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) ReviewReading(w http.ResponseWriter, r *http.Request) {
	var input cases.ReviewReadingInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.ReviewReading(r.PathValue("incidentID"), r.PathValue("readingID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) GetContextSnapshots(w http.ResponseWriter, r *http.Request) {
	v, err := a.service.ContextSnapshot(r.PathValue("incidentID"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: v})
}

func (a *API) GetReassessmentTasks(w http.ResponseWriter, r *http.Request) {
	var from, to time.Time
	var err error
	if raw := r.URL.Query().Get("from"); raw != "" {
		from, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			writeAPIError(w, r, 400, "INVALID_ARGUMENT", "from 时间格式无效")
			return
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		to, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			writeAPIError(w, r, 400, "INVALID_ARGUMENT", "to 时间格式无效")
			return
		}
	}
	v, err := a.service.ReassessmentTasks(r.PathValue("incidentID"), r.URL.Query().Get("status"), r.URL.Query().Get("owner_id"), from, to)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: v, Meta: map[string]any{"count": len(v)}})
}

func (a *API) GetInspectionReport(w http.ResponseWriter, r *http.Request) {
	report, err := a.service.InspectionReport(r.PathValue("incidentID"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: report})
}

func (a *API) ValidateHypothesis(w http.ResponseWriter, r *http.Request) {
	var input cases.ValidateHypothesisInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.ValidateHypothesis(r.PathValue("incidentID"), r.PathValue("hypothesisID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) AcknowledgeDeadline(w http.ResponseWriter, r *http.Request) {
	var input cases.AcknowledgeDeadlineInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.AcknowledgeDeadline(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) CompleteDeadlineCommitment(w http.ResponseWriter, r *http.Request) {
	var input cases.CompleteCommitmentInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.CompleteDeadlineCommitment(r.PathValue("incidentID"), r.PathValue("commitmentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) HandoverSensor(w http.ResponseWriter, r *http.Request) {
	var input cases.SensorHandoverInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.HandoverSensor(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) SubmitPlan(w http.ResponseWriter, r *http.Request) {
	var input cases.SubmitPlanInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.SubmitPlan(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) GetPlanDiff(w http.ResponseWriter, r *http.Request) {
	fromRaw, toRaw := r.URL.Query().Get("from_version"), r.URL.Query().Get("to_version")
	if fromRaw == "" {
		fromRaw = r.URL.Query().Get("from")
	}
	if toRaw == "" {
		toRaw = r.URL.Query().Get("to")
	}
	from, err1 := strconv.Atoi(fromRaw)
	to, err2 := strconv.Atoi(toRaw)
	if err1 != nil || err2 != nil {
		writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "from_version 和 to_version 必须为整数")
		return
	}
	diff, err := a.service.PlanDiff(r.PathValue("incidentID"), from, to)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: diff})
}

func (a *API) ReviewPlan(w http.ResponseWriter, r *http.Request) {
	var input cases.ReviewPlanInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.ReviewPlan(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) RecordExecution(w http.ResponseWriter, r *http.Request) {
	var input cases.ExecuteInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.RecordExecution(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) GetMaterials(w http.ResponseWriter, r *http.Request) {
	days := 7
	if raw := r.URL.Query().Get("warning_days"); raw != "" {
		v, e := strconv.Atoi(raw)
		if e != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "warning_days 必须为整数")
			return
		}
		days = v
	}
	items, err := a.service.MaterialTracking(r.PathValue("incidentID"), days)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: items, Meta: map[string]any{"count": len(items), "warning_days": days}})
}

func (a *API) GetMaterialTracking(w http.ResponseWriter, r *http.Request) {
	items, err := a.service.MaterialBatchTracking(r.URL.Query().Get("batch_number"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: items, Meta: map[string]any{"count": len(items)}})
}

func (a *API) ReviewDeviation(w http.ResponseWriter, r *http.Request) {
	var input cases.ReviewDeviationInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.ReviewDeviation(r.PathValue("incidentID"), r.PathValue("executionID"), r.PathValue("deviationID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) AddObservations(w http.ResponseWriter, r *http.Request) {
	var input cases.AddObservationInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.AddObservations(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) VerifyRecovery(w http.ResponseWriter, r *http.Request) {
	var input cases.VerifyRecoveryInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.VerifyRecovery(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) GetRecoveryProgress(w http.ResponseWriter, r *http.Request) {
	now := time.Time{}
	if raw := r.URL.Query().Get("now"); raw != "" {
		var e error
		now, e = time.Parse(time.RFC3339, raw)
		if e != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "now 时间格式无效")
			return
		}
	}
	progress, err := a.service.RecoveryProgressAt(r.PathValue("incidentID"), now)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: progress})
}

func (a *API) GetVerificationHistory(w http.ResponseWriter, r *http.Request) {
	view, err := a.service.VerificationHistory(r.PathValue("incidentID"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: view})
}

func (a *API) GetReopenReadiness(w http.ResponseWriter, r *http.Request) {
	readiness, err := a.service.ReopenReadiness(r.PathValue("incidentID"), strings.TrimSpace(r.Header.Get("X-Actor-Role")))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: readiness})
}

func (a *API) PlaceReopenHold(w http.ResponseWriter, r *http.Request) {
	var input cases.PlaceReopenHoldInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.PlaceReopenHold(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) ResolveHoldRequirement(w http.ResponseWriter, r *http.Request) {
	var input cases.ResolveHoldRequirementInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.ResolveHoldRequirement(r.PathValue("incidentID"), r.PathValue("holdID"), r.PathValue("requirementID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) RenewReopenHold(w http.ResponseWriter, r *http.Request) {
	var input cases.RenewReopenHoldInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.RenewReopenHold(r.PathValue("incidentID"), r.PathValue("holdID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) SignReopen(w http.ResponseWriter, r *http.Request) {
	var input cases.SignReopenInput
	if !decodeCommand(w, r, &input, &input.Meta) {
		return
	}
	incident, replayed, err := a.service.SignReopen(r.PathValue("incidentID"), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeCommand(w, http.StatusOK, incident, replayed)
}

func (a *API) GetIncident(w http.ResponseWriter, r *http.Request) {
	incident, err := a.service.Get(r.PathValue("incidentID"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: incident})
}

func (a *API) ListIncidents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	stats := false
	if raw := query.Get("stats"); raw != "" {
		value, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "stats 必须为布尔值")
			return
		}
		stats = value
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "limit 必须为整数")
			return
		}
		limit = value
	}
	statuses := []store.Status{}
	for _, value := range query["status"] {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				statuses = append(statuses, store.Status(part))
			}
		}
	}
	risks := []string{}
	for _, value := range query["risk_level"] {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				risks = append(risks, part)
			}
		}
	}
	parseTime := func(name string) (time.Time, bool) {
		raw := query.Get(name)
		if raw == "" {
			return time.Time{}, true
		}
		t, e := time.Parse(time.RFC3339, raw)
		if e != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", name+" 时间格式无效")
			return time.Time{}, false
		}
		return t, true
	}
	fromName := "opened_from"
	if query.Get(fromName) == "" && query.Get("opened_at_from") != "" {
		fromName = "opened_at_from"
	}
	toName := "opened_to"
	if query.Get(toName) == "" && query.Get("opened_at_to") != "" {
		toName = "opened_at_to"
	}
	from, ok := parseTime(fromName)
	if !ok {
		return
	}
	to, ok := parseTime(toName)
	if !ok {
		return
	}
	page, err := a.service.Query(cases.ListQuery{ArtifactID: query.Get("artifact_id"), SensorID: query.Get("sensor_id"), CaseNumber: query.Get("case_number"), OpenedFrom: from, OpenedTo: to, Statuses: statuses, RiskLevels: risks, DisplayCaseID: query.Get("display_case_id"), DeadlineStatus: store.DeadlineStatus(query.Get("deadline_status")), EscalationStatus: store.EscalationStatus(query.Get("escalation_status")), CommitmentOwnerID: query.Get("owner_id"), EvidenceGap: query.Get("evidence_gap"), Stats: stats, Limit: limit, Cursor: query.Get("cursor")})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	meta := map[string]any{"count": len(page.Items), "next_cursor": page.NextCursor, "deadline_counts": page.DeadlineCounts, "escalation_counts": page.EscalationCounts, "unacknowledged_count": page.EscalationCounts[store.EscalationOverdueUnacknowledged]}
	if page.Stats != nil {
		meta["stats"] = page.Stats
		meta["generated_at"] = page.Stats.GeneratedAt
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: page.Items, Meta: meta})
}

func (a *API) GetTimeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if raw := q.Get("limit"); raw != "" {
		v, e := strconv.Atoi(raw)
		if e != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "limit 必须为整数")
			return
		}
		limit = v
	}
	var from, to time.Time
	var e error
	if q.Get("from") != "" {
		from, e = time.Parse(time.RFC3339, q.Get("from"))
		if e != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "from 时间格式无效")
			return
		}
	}
	if q.Get("to") != "" {
		to, e = time.Parse(time.RFC3339, q.Get("to"))
		if e != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "to 时间格式无效")
			return
		}
	}
	page, err := a.service.TimelinePage(r.PathValue("incidentID"), cases.TimelineQuery{EventType: q.Get("event_type"), ActorID: q.Get("actor_id"), From: from, To: to, Limit: limit, Cursor: q.Get("cursor")})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: page.Events, Meta: map[string]any{"count": len(page.Events), "match_count": page.MatchCount, "next_cursor": page.NextCursor, "evidence_gaps": page.EvidenceGaps}})
}

func (a *API) GetEvidence(w http.ResponseWriter, r *http.Request) {
	summary, err := a.service.Evidence(r.PathValue("incidentID"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, responseEnvelope{Data: summary})
}

func (a *API) GetRiskHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var from, to time.Time
	var e error
	if q.Get("from") != "" {
		from, e = time.Parse(time.RFC3339, q.Get("from"))
		if e != nil {
			writeAPIError(w, r, 400, "INVALID_ARGUMENT", "from 时间格式无效")
			return
		}
	}
	if q.Get("to") != "" {
		to, e = time.Parse(time.RFC3339, q.Get("to"))
		if e != nil {
			writeAPIError(w, r, 400, "INVALID_ARGUMENT", "to 时间格式无效")
			return
		}
	}
	v, e := a.service.RiskHistory(r.PathValue("incidentID"), from, to)
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	writeJSON(w, 200, responseEnvelope{Data: v, Meta: map[string]any{"count": len(v.Items)}})
}
func (a *API) GetFollowUps(w http.ResponseWriter, r *http.Request) {
	now := time.Time{}
	var e error
	if raw := r.URL.Query().Get("now"); raw != "" {
		now, e = time.Parse(time.RFC3339, raw)
		if e != nil {
			writeAPIError(w, r, 400, "INVALID_ARGUMENT", "now 时间格式无效")
			return
		}
	}
	v, e := a.service.FollowUps(r.PathValue("incidentID"), r.URL.Query().Get("conclusion"), now)
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	writeJSON(w, 200, responseEnvelope{Data: v})
}
func (a *API) PlanPreflight(w http.ResponseWriter, r *http.Request) {
	var in cases.SubmitPlanInput
	if !decodeCommand(w, r, &in, &in.Meta) {
		return
	}
	v, e := a.service.PlanPreflight(r.PathValue("incidentID"), in)
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	writeJSON(w, 200, responseEnvelope{Data: v})
}
func (a *API) GetExecutionSummary(w http.ResponseWriter, r *http.Request) {
	v, e := a.service.ExecutionSummary(r.PathValue("incidentID"), r.URL.Query().Get("execution_id"))
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	writeJSON(w, 200, responseEnvelope{Data: v})
}
func (a *API) GetReopenPreview(w http.ResponseWriter, r *http.Request) {
	rev := int64(0)
	if raw := r.URL.Query().Get("revision"); raw != "" {
		v, e := strconv.ParseInt(raw, 10, 64)
		if e != nil {
			writeAPIError(w, r, 400, "INVALID_ARGUMENT", "revision 必须为整数")
			return
		}
		rev = v
	}
	v, e := a.service.ReopenPreview(r.PathValue("incidentID"), strings.TrimSpace(r.Header.Get("X-Actor-Role")), rev)
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	if v.Stale {
		writeAPIError(w, r, http.StatusConflict, "PRECONDITION_FAILED", "revision 已变化，预览已过期")
		return
	}
	writeJSON(w, 200, responseEnvelope{Data: v})
}
func (a *API) ExpireCommitment(w http.ResponseWriter, r *http.Request) {
	var in cases.ExpireInput
	if !decodeCommand(w, r, &in, &in.Meta) {
		return
	}
	v, re, e := a.service.ExpireCommitment(r.PathValue("incidentID"), r.PathValue("commitmentID"), in)
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	writeCommand(w, 200, v, re)
}
func (a *API) RenewCommitment(w http.ResponseWriter, r *http.Request) {
	var in cases.RenewInput
	if !decodeCommand(w, r, &in, &in.Meta) {
		return
	}
	v, re, e := a.service.RenewCommitment(r.PathValue("incidentID"), r.PathValue("commitmentID"), in)
	if e != nil {
		writeDomainError(w, r, e)
		return
	}
	writeCommand(w, 200, v, re)
}

func decodeCommand(w http.ResponseWriter, r *http.Request, destination any, meta *cases.CommandMeta) bool {
	if !decodeJSON(w, r, destination) {
		return false
	}
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" {
		meta.RequestID = value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Actor-ID")); value != "" {
		meta.ActorID = value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Actor-Role")); value != "" {
		meta.ActorRole = value
	}
	if value := strings.TrimSpace(r.Header.Get("If-Match")); value != "" {
		value = strings.Trim(value, "\"")
		revision, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REVISION", "If-Match 必须是整数 revision")
			return false
		}
		meta.ExpectedRevision = revision
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		writeAPIError(w, r, http.StatusUnsupportedMediaType, "CONTENT_TYPE_REQUIRED", "请求体必须使用 application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			writeAPIError(w, r, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "请求体不能超过 1 MiB")
		} else {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_JSON", "请求 JSON 无效："+err.Error())
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeAPIError(w, r, http.StatusBadRequest, "INVALID_JSON", "请求体只能包含一个 JSON 对象")
		return false
	}
	return true
}

func writeCommand(w http.ResponseWriter, successStatus int, data any, replayed bool) {
	status := successStatus
	if replayed {
		status = http.StatusOK
		w.Header().Set("Idempotent-Replay", "true")
	}
	writeJSON(w, status, responseEnvelope{Data: data, Meta: map[string]any{"replayed": replayed}})
}

func writeDomainError(w http.ResponseWriter, r *http.Request, err error) {
	var domain *cases.Error
	if !errors.As(err, &domain) {
		writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "服务处理请求失败")
		return
	}
	status := http.StatusBadRequest
	switch domain.Code {
	case "INCIDENT_NOT_FOUND":
		status = http.StatusNotFound
	case "REVISION_CONFLICT":
		status = http.StatusConflict
	case "INCIDENT_ALREADY_EXISTS":
		status = http.StatusConflict
	case "ACTIVE_INCIDENT_CONFLICT":
		status = http.StatusConflict
	case "CAUSE_HYPOTHESIS_CONFLICT", "SEALED":
		status = http.StatusConflict
	case "PRECONDITION_FAILED":
		status = http.StatusUnprocessableEntity
	case "INTERNAL_ERROR":
		status = http.StatusInternalServerError
	case "EVIDENCE_INTEGRITY_FAILED":
		status = http.StatusConflict
	}
	writeAPIErrorDetails(w, r, status, domain.Code, domain.Message, domain.Details)
}

func writeAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeAPIErrorDetails(w, r, status, code, message, nil)
}

func writeAPIErrorDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details map[string]any) {
	writeJSON(w, status, errorBody{Error: apiError{Code: code, Message: message, RequestID: requestID(r), Details: details}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Printf("编码 HTTP 响应失败: %v\n", err)
	}
}

type contextKey string

const requestIDKey contextKey = "request_id"

func requestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func requestID(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" {
		return value
	}
	return ""
}
