package recoveryprogresscachetime_test

import (
	"path/filepath"
	"testing"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

func TestRecoveryProgressCacheSeparatesEvaluationTime(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	capturedAt := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	incident := &store.EnvironmentIncident{
		IncidentID:               "incident-recovery-cache",
		CaseNumber:               "ME-RECOVERY-CACHE",
		DisplayCaseID:            "display-case-1",
		ArtifactID:               "artifact-1",
		SensorID:                 "sensor-1",
		Sensitivity:              "medium",
		RiskLevel:                "moderate",
		ResponseDeadline:         capturedAt.Add(48 * time.Hour),
		Status:                   store.StatusObserving,
		CurrentObservationWindow: 1,
		Plan: &store.InterventionPlan{
			PlanID:                 "plan-1",
			Version:                1,
			ReviewStatus:           "approved",
			TargetTemperatureRange: store.Range{Min: 18, Max: 22},
			TargetHumidityRange:    store.Range{Min: 45, Max: 55},
		},
		Readings: []store.EnvironmentReading{{
			ReadingID:               "recovery-reading-1",
			IncidentID:              "incident-recovery-cache",
			CapturedAt:              capturedAt,
			TemperatureCelsius:      20,
			RelativeHumidityPercent: 50,
			SensorStatus:            "ok",
			SensorID:                "sensor-1",
			Phase:                   "recovery",
			ObservationWindow:       1,
			ObservationSegment:      1,
			EligibleForRecovery:     true,
		}},
	}
	if _, _, err := repository.Create(store.Mutation{
		RequestID:  "create-recovery-cache",
		Operation:  "create_incident",
		IncidentID: incident.IncidentID,
		ActorID:    "operator-1",
		EventType:  "incident.reported",
		Payload:    map[string]string{"source": "private-reproduction"},
	}, incident); err != nil {
		t.Fatalf("create incident: %v", err)
	}

	service := cases.NewService(repository)
	onTime, err := service.RecoveryProgressAt(incident.IncidentID, capturedAt)
	if err != nil {
		t.Fatalf("first recovery progress: %v", err)
	}
	if onTime.SamplingStatus != "on_time" || len(onTime.Segments) != 1 {
		t.Fatalf("unexpected first progress: status=%s segments=%d", onTime.SamplingStatus, len(onTime.Segments))
	}
	onTime.Segments[0].ValidReadings = 999

	overdue, err := service.RecoveryProgressAt(incident.IncidentID, capturedAt.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("second recovery progress: %v", err)
	}
	if overdue.SamplingStatus != "overdue" || overdue.Segments[0].ValidReadings != 1 {
		t.Fatalf("cached progress crossed evaluation time and ownership boundary: status=%s valid_readings=%d", overdue.SamplingStatus, overdue.Segments[0].ValidReadings)
	}
}
