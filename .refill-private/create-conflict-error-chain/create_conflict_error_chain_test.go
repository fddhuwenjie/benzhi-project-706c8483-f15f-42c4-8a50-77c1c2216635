package createconflicterrorchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/httpapi"
	"museumenv/internal/store"
)

type activeConflictRepository struct{}

func (*activeConflictRepository) Create(store.Mutation, *store.EnvironmentIncident) (*store.EnvironmentIncident, bool, error) {
	return nil, false, &store.ActiveIncidentError{
		IncidentID: "inc-existing",
		CaseNumber: "ME-20260826-EXISTING",
		Status:     store.StatusInspected,
		Revision:   4,
	}
}

func (*activeConflictRepository) Update(store.Mutation, store.MutateFunc) (*store.EnvironmentIncident, bool, error) {
	return nil, false, errors.New("unexpected Update")
}

func (*activeConflictRepository) Get(string) (*store.EnvironmentIncident, error) {
	return nil, errors.New("unexpected Get")
}

func (*activeConflictRepository) List() ([]store.EnvironmentIncident, error) {
	return nil, nil
}

func (*activeConflictRepository) Query(store.IncidentQuery) (store.IncidentPage, error) {
	return store.IncidentPage{}, errors.New("unexpected Query")
}

func (*activeConflictRepository) Timeline(string) ([]store.AuditEvent, error) {
	return nil, errors.New("unexpected Timeline")
}

func (*activeConflictRepository) Evidence(string) (store.EvidenceSummary, error) {
	return store.EvidenceSummary{}, errors.New("unexpected Evidence")
}

func TestCreateConflictPreservesStoreErrorChain(t *testing.T) {
	now := time.Now().UTC()
	body := map[string]any{
		"meta": map[string]any{
			"request_id": "create-conflict-request",
			"actor_id":   "operator-01",
			"actor_role": "preventive_conservator",
		},
		"display_case_id":           "case-A01",
		"artifact_id":               "artifact-001",
		"sensor_id":                 "sensor-TH-01",
		"sensitivity":               "high",
		"abnormal_since":            now.Add(-time.Hour),
		"temperature_celsius":       27.0,
		"relative_humidity_percent": 68.0,
		"target_temperature_range":  map[string]any{"min": 18.0, "max": 22.0},
		"target_humidity_range":     map[string]any{"min": 45.0, "max": 55.0},
		"sensor_status":             "ok",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/environment-incidents", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	httpapi.New(cases.NewService(&activeConflictRepository{})).Handler().ServeHTTP(response, request)

	var envelope struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Code != http.StatusConflict || envelope.Error.Code != "ACTIVE_INCIDENT_CONFLICT" {
		t.Fatalf("active incident conflict lost across service boundary: status=%d code=%s body=%s", response.Code, envelope.Error.Code, response.Body.String())
	}
	if envelope.Error.Details["incident_id"] != "inc-existing" || envelope.Error.Details["revision"] != float64(4) {
		t.Fatalf("active incident details were not preserved: %#v", envelope.Error.Details)
	}
}
