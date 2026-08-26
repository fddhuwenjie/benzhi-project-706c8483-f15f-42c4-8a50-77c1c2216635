package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

func TestBatchRegistrationAndDeadlineAcknowledgementFlow(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(cases.NewService(repository)).Handler())
	defer server.Close()
	now := time.Now().UTC().Truncate(time.Second)
	create := map[string]any{
		"meta":            map[string]any{"request_id": "batch-create", "actor_id": "operator-1", "actor_role": "preventive_conservator"},
		"display_case_id": "Case-A", "artifact_id": "Artifact-A", "sensor_id": "Sensor-A", "sensitivity": "high", "abnormal_since": now.Add(-2 * time.Hour),
		"target_temperature_range": map[string]any{"min": 18, "max": 22}, "target_humidity_range": map[string]any{"min": 45, "max": 55},
		"discovery_readings": []map[string]any{
			{"captured_at": now.Add(-20 * time.Minute), "temperature_celsius": 24, "relative_humidity_percent": 60, "sensor_status": "ok"},
			{"captured_at": now.Add(-10 * time.Minute), "temperature_celsius": 35, "relative_humidity_percent": 90, "sensor_status": "warning"},
			{"captured_at": now, "temperature_celsius": 23, "relative_humidity_percent": 58, "sensor_status": "ok"},
		},
	}
	var incident store.EnvironmentIncident
	postJSON(t, server.URL+"/v1/environment-incidents", create, http.StatusCreated, &incident)
	if incident.Revision != 1 || len(incident.Readings) != 3 || incident.PeakReadingID != incident.Readings[1].ReadingID || incident.RiskLevel != "critical" {
		t.Fatalf("incident = %+v", incident)
	}
	originalDeadline := incident.ResponseDeadline
	invalid := create
	invalid["meta"] = map[string]any{"request_id": "batch-invalid", "actor_id": "operator-1"}
	invalid["sensor_id"] = "sensor-b"
	invalid["discovery_readings"] = []map[string]any{
		{"captured_at": now, "temperature_celsius": 25, "relative_humidity_percent": 60, "sensor_status": "ok"},
		{"captured_at": now, "temperature_celsius": 26, "relative_humidity_percent": 61, "sensor_status": "ok"},
	}
	postJSON(t, server.URL+"/v1/environment-incidents", invalid, http.StatusBadRequest, nil)
	items, err := repository.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
	events, err := repository.Timeline(incident.IncidentID)
	if err != nil || len(events) != 1 {
		t.Fatalf("events after rejected batch = %+v, err = %v", events, err)
	}
	acknowledge := map[string]any{
		"meta":   map[string]any{"request_id": "ack-1", "actor_id": "supervisor-1", "actor_role": "duty_supervisor", "expected_revision": 1},
		"reason": "严重风险即将到期", "owner_id": "Engineer-A", "next_action": "检查冷却设备", "commitment_due_at": now.Add(time.Hour),
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/deadline-acknowledgements", acknowledge, http.StatusOK, &incident)
	if incident.Revision != 2 || !incident.ResponseDeadline.Equal(originalDeadline) || len(incident.DeadlineCommitments) != 1 || incident.CommitmentOwnerID != "engineer-a" {
		t.Fatalf("acknowledged incident = %+v", incident)
	}
	inspection := map[string]any{
		"meta":    map[string]any{"request_id": "inspection-1", "actor_id": "inspector-1", "actor_role": "preventive_conservator", "expected_revision": 2},
		"finding": "冷却设备停止且传感器读数可复核", "isolation_measure": "关闭展柜并设置围挡",
		"cause_hypotheses": []map[string]any{
			{"description": "冷却设备故障", "conclusion": "supported", "verification_method": "现场通电检查", "evidence": "设备无启动电流"},
			{"description": "传感器漂移", "conclusion": "excluded", "verification_method": "与校准仪表比对", "evidence": "差值在允许范围"},
		},
		"independent_reading": map[string]any{"captured_at": now.Add(-5 * time.Minute), "temperature_celsius": 24, "relative_humidity_percent": 60, "sensor_status": "ok", "calibration_reference": "field-ref-1"},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/inspection", inspection, http.StatusOK, &incident)
	if len(incident.Inspection.Hypotheses) != 2 || incident.Inspection.Hypotheses[0].CurrentConclusion != "supported" || incident.Inspection.Hypotheses[1].CurrentConclusion != "excluded" {
		t.Fatalf("inspection hypotheses = %+v", incident.Inspection.Hypotheses)
	}
	plan := map[string]any{
		"meta":  map[string]any{"request_id": "plan-1", "actor_id": "planner-1", "actor_role": "preventive_conservator", "expected_revision": 3},
		"steps": []string{"更换调湿材料"}, "target_temperature_range": map[string]any{"min": 18, "max": 22}, "target_humidity_range": map[string]any{"min": 45, "max": 55}, "isolation_required": true,
		"safety_envelope": map[string]any{"max_temperature_change_per_hour": 0.5, "max_humidity_change_per_hour": 2, "max_exposure_minutes": 30, "stop_temperature_range": map[string]any{"min": 10, "max": 30}, "stop_humidity_range": map[string]any{"min": 20, "max": 80}, "rollback_steps": []string{"停止调节并恢复原材料"}, "rollback_owner_id": "engineer-1"},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/plans", plan, http.StatusOK, &incident)
	review := map[string]any{"meta": map[string]any{"request_id": "review-1", "actor_id": "engineer-1", "actor_role": "conservation_engineer", "expected_revision": 4}, "decision": "approve", "note": "安全包络符合高敏感展品要求"}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/plan-review", review, http.StatusOK, &incident)
	if incident.Plan.SafetyFrozenAt == nil {
		t.Fatal("approved safety envelope was not frozen")
	}
	execution := map[string]any{
		"meta":        map[string]any{"request_id": "execution-1", "actor_id": "operator-2", "actor_role": "preventive_conservator", "expected_revision": 5},
		"executed_at": now.Add(-90 * time.Minute), "duration_minutes": 30, "notes": "使用等效材料完成执行",
		"step_results":       []map[string]any{{"step_number": 1, "result": "completed"}},
		"materials":          []map[string]any{{"name": "调湿材料", "batch_number": "batch-sub-1", "quantity": 1, "expires_at": now.AddDate(1, 0, 0)}},
		"calibration_before": map[string]any{"captured_at": now.Add(-121 * time.Minute), "temperature_celsius": 20, "relative_humidity_percent": 50, "sensor_status": "ok", "calibration_reference": "cal-ref-1"},
		"calibration_after":  map[string]any{"captured_at": now.Add(-91 * time.Minute), "temperature_celsius": 20.2, "relative_humidity_percent": 50.5, "sensor_status": "ok", "calibration_reference": "cal-ref-1"},
		"deviations":         []map[string]any{{"type": "material_substitution", "reason": "原批次包装破损", "immediate_control": "核验等效材料有效期和规格", "plan_step_number": 1}},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/execution", execution, http.StatusOK, &incident)
	deviation := incident.Execution.Deviations[0]
	if incident.Execution.DeviationGate != "pending_review" || deviation.CurrentDecision != "pending" {
		t.Fatalf("execution deviations = %+v", incident.Execution)
	}
	observations := map[string]any{
		"meta":     map[string]any{"request_id": "observe-blocked", "actor_id": "operator-2", "actor_role": "preventive_conservator", "expected_revision": 6},
		"readings": []map[string]any{{"captured_at": now.Add(-80 * time.Minute), "temperature_celsius": 20, "relative_humidity_percent": 50, "sensor_status": "ok"}},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/observations", observations, http.StatusUnprocessableEntity, nil)
	deviationReview := map[string]any{"meta": map[string]any{"request_id": "deviation-review-1", "actor_id": "engineer-1", "actor_role": "conservation_engineer", "expected_revision": 6}, "decision": "approve_observation", "risk_explanation": "替代材料规格等效且控制措施充分"}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/executions/"+incident.Execution.ExecutionID+"/deviations/"+deviation.DeviationID+"/review", deviationReview, http.StatusOK, &incident)
	observations["meta"] = map[string]any{"request_id": "observe-1", "actor_id": "operator-2", "actor_role": "preventive_conservator", "expected_revision": 7}
	observations["readings"] = []map[string]any{
		{"captured_at": now.Add(-80 * time.Minute), "temperature_celsius": 20, "relative_humidity_percent": 50, "sensor_status": "ok"},
		{"captured_at": now.Add(-65 * time.Minute), "temperature_celsius": 20.1, "relative_humidity_percent": 50, "sensor_status": "ok"},
		{"captured_at": now.Add(-50 * time.Minute), "temperature_celsius": 20, "relative_humidity_percent": 50.2, "sensor_status": "ok"},
		{"captured_at": now.Add(-35 * time.Minute), "temperature_celsius": 20.1, "relative_humidity_percent": 50.1, "sensor_status": "ok"},
		{"captured_at": now.Add(-20 * time.Minute), "temperature_celsius": 20, "relative_humidity_percent": 50, "sensor_status": "ok"},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/observations", observations, http.StatusOK, &incident)
	if incident.RecoveryProgress == nil || !incident.RecoveryProgress.Qualified {
		t.Fatalf("recovery progress = %+v", incident.RecoveryProgress)
	}
	progressRevision := incident.Revision
	var progress cases.RecoveryProgressView
	getJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/recovery-progress", "", http.StatusOK, &progress)
	var afterProgress store.EnvironmentIncident
	getJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID, "", http.StatusOK, &afterProgress)
	if afterProgress.Revision != progressRevision || !progress.Progress.Qualified {
		t.Fatalf("progress changed revision or was not qualified: revision=%d progress=%+v", afterProgress.Revision, progress)
	}
	verification := map[string]any{"meta": map[string]any{"request_id": "verify-1", "actor_id": "verifier-1", "actor_role": "preventive_conservator", "expected_revision": 8}, "minimum_stable_minutes": 60, "minimum_readings": 5}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/verification", verification, http.StatusOK, &incident)
	var readiness cases.ReadinessView
	getJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/reopen-readiness", "duty_supervisor", http.StatusOK, &readiness)
	if !readiness.Ready || incident.Revision != 9 {
		t.Fatalf("readiness = %+v, revision = %d", readiness, incident.Revision)
	}
	hold := map[string]any{"meta": map[string]any{"request_id": "hold-1", "actor_id": "supervisor-1", "actor_role": "duty_supervisor", "expected_revision": 9}, "reason_code": "additional_calibration_evidence", "requirements": []string{"补充校准证书"}, "review_due_at": now.Add(2 * time.Hour)}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/reopen-holds", hold, http.StatusOK, &incident)
	sign := map[string]any{"meta": map[string]any{"request_id": "sign-blocked", "actor_id": "supervisor-1", "actor_role": "duty_supervisor", "expected_revision": 10}, "decision": "reopen", "note": "尝试签署"}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/reopen-signature", sign, http.StatusUnprocessableEntity, nil)
	holdRecord := incident.ReopenHolds[0]
	resolve := map[string]any{"meta": map[string]any{"request_id": "resolve-1", "actor_id": "inspector-1", "actor_role": "preventive_conservator", "expected_revision": 10}, "resolution": "已上传在有效期内的校准证书", "evidence_ref": "calibration-evidence-2026"}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/reopen-holds/"+holdRecord.HoldID+"/requirements/"+holdRecord.Requirements[0].RequirementID+"/resolve", resolve, http.StatusOK, &incident)
	sign["meta"] = map[string]any{"request_id": "sign-1", "actor_id": "supervisor-1", "actor_role": "duty_supervisor", "expected_revision": 11}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/reopen-signature", sign, http.StatusOK, &incident)
	if incident.Status != store.StatusSealed || incident.ReopenHolds[0].Requirements[0].ResolvedAt == nil {
		t.Fatalf("sealed incident = %+v", incident)
	}
}

func TestRegistrationQualitySnapshotAndReplay(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(cases.NewService(repository)).Handler())
	defer server.Close()
	now := time.Now().UTC().Truncate(time.Second)
	create := map[string]any{
		"meta":            map[string]any{"request_id": "quality-create", "actor_id": "operator-1", "actor_role": "preventive_conservator"},
		"display_case_id": "quality-case", "artifact_id": "artifact-q", "sensor_id": "sensor-q", "sensitivity": "high", "abnormal_since": now.Add(-time.Hour),
		"target_temperature_range": map[string]any{"min": 18, "max": 22}, "target_humidity_range": map[string]any{"min": 45, "max": 55},
		"calibration_reference": "CAL-Q-1", "calibration_expires_at": now.Add(24 * time.Hour),
		"discovery_readings": []map[string]any{
			{"captured_at": now.Add(-20 * time.Minute), "temperature_celsius": 24, "relative_humidity_percent": 60, "sensor_status": "ok", "quality": "ok"},
			{"captured_at": now.Add(-10 * time.Minute), "temperature_celsius": 40, "relative_humidity_percent": 95, "sensor_status": "warning", "quality": "warning", "quality_note": "自检告警"},
			{"captured_at": now, "temperature_celsius": 25, "relative_humidity_percent": 62, "sensor_status": "ok", "quality": "ok"},
		},
	}
	var incident store.EnvironmentIncident
	postJSON(t, server.URL+"/v1/environment-incidents", create, http.StatusCreated, &incident)
	if incident.BaselineVersion == "" || incident.CalibrationReference != "CAL-Q-1" || incident.Readings[1].QualityFlag != "warning" || incident.PeakReadingID == incident.Readings[1].ReadingID {
		t.Fatalf("quality snapshot = %+v", incident)
	}
	firstID, firstRevision := incident.IncidentID, incident.Revision
	postJSON(t, server.URL+"/v1/environment-incidents", create, http.StatusOK, &incident)
	if incident.IncidentID != firstID || incident.Revision != firstRevision {
		t.Fatalf("replay changed snapshot: %+v", incident)
	}
	expired := create
	expired["meta"] = map[string]any{"request_id": "expired-create", "actor_id": "operator-1"}
	expired["display_case_id"] = "expired-case"
	expired["sensor_id"] = "expired-sensor"
	expired["calibration_expires_at"] = now.Add(-time.Minute)
	postJSON(t, server.URL+"/v1/environment-incidents", expired, http.StatusBadRequest, nil)
	items, err := repository.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("rejected registration changed store: items=%d err=%v", len(items), err)
	}
	response, err := server.Client().Get(server.URL + "/v1/environment-incidents?stats=true&risk_level=" + incident.RiskLevel)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var list struct {
		Meta struct {
			Stats       store.IncidentStats `json:"stats"`
			GeneratedAt time.Time           `json:"generated_at"`
		} `json:"meta"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&list) != nil {
		t.Fatalf("stats response status=%d", response.StatusCode)
	}
	if list.Meta.Stats.IncidentCount != 1 || list.Meta.GeneratedAt.IsZero() || len(list.Meta.Stats.EvidenceGapIncidentIDs) != 1 {
		t.Fatalf("stats = %+v", list.Meta)
	}
}

func TestUntrustworthySensorCanBeHandedOverWithOverlapEvidence(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(cases.NewService(repository)).Handler())
	defer server.Close()
	now := time.Now().UTC().Truncate(time.Second)
	create := map[string]any{
		"meta":            map[string]any{"request_id": "handover-create", "actor_id": "operator-1"},
		"display_case_id": "case-h", "artifact_id": "artifact-h", "sensor_id": "sensor-old", "sensitivity": "medium", "abnormal_since": now.Add(-time.Hour),
		"temperature_celsius": 20, "relative_humidity_percent": 50, "sensor_status": "ok", "target_temperature_range": map[string]any{"min": 18, "max": 22}, "target_humidity_range": map[string]any{"min": 45, "max": 55},
	}
	var incident store.EnvironmentIncident
	postJSON(t, server.URL+"/v1/environment-incidents", create, http.StatusCreated, &incident)
	inspection := map[string]any{
		"meta": map[string]any{"request_id": "handover-inspection", "actor_id": "inspector-1", "expected_revision": 1}, "finding": "传感器与独立仪表偏差明显", "cause_hypotheses": []string{"传感器漂移"}, "isolation_measure": "暂停开放并隔离展柜", "alternative_monitoring": "交接前由校准便携仪表连续监测", "alternative_review_at": now.Add(time.Hour),
		"independent_reading": map[string]any{"captured_at": now.Add(-30 * time.Minute), "temperature_celsius": 25, "relative_humidity_percent": 60, "sensor_status": "ok", "calibration_reference": "field-reference"},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/inspection", inspection, http.StatusOK, &incident)
	if incident.Inspection.SensorTrustworthy {
		t.Fatal("sensor should have been classified as untrustworthy")
	}
	removedAt, installedAt, overlapAt := now.Add(-2*time.Minute), now.Add(-time.Minute), now.Add(-90*time.Second)
	handover := map[string]any{
		"meta": map[string]any{"request_id": "handover-1", "actor_id": "operator-2", "expected_revision": 2}, "new_sensor_id": "Sensor-New", "removed_at": removedAt, "installed_at": installedAt, "handed_over_by": "operator-2", "reason": "原传感器漂移", "calibration_reference": "shared-reference",
		"old_sensor_readings": []map[string]any{{"captured_at": overlapAt, "temperature_celsius": 20, "relative_humidity_percent": 50, "sensor_status": "ok"}},
		"new_sensor_readings": []map[string]any{{"captured_at": overlapAt, "temperature_celsius": 20.5, "relative_humidity_percent": 52, "sensor_status": "ok"}},
	}
	postJSON(t, server.URL+"/v1/environment-incidents/"+incident.IncidentID+"/sensor-handover", handover, http.StatusOK, &incident)
	if incident.SensorID != "sensor-new" || len(incident.SensorHandovers) != 1 || incident.SensorHandovers[0].OldReadings[0].SensorID != "sensor-old" || incident.SensorHandovers[0].NewReadings[0].SensorID != "sensor-new" {
		t.Fatalf("handover = %+v", incident.SensorHandovers)
	}
}

func postJSON(t *testing.T, url string, body any, expectedStatus int, destination any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		t.Fatalf("status = %d, want %d", response.StatusCode, expectedStatus)
	}
	if destination != nil {
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(envelope.Data, destination); err != nil {
			t.Fatal(err)
		}
	}
}

func getJSON(t *testing.T, url, role string, expectedStatus int, destination any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if role != "" {
		request.Header.Set("X-Actor-Role", role)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		t.Fatalf("status = %d, want %d", response.StatusCode, expectedStatus)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Data, destination); err != nil {
		t.Fatal(err)
	}
}
