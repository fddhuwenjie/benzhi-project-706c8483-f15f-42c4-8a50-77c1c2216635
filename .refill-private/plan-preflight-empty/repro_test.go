package planpreflightempty

import (
	"testing"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

func TestPlanPreflightRejectsEmptySteps(t *testing.T) {
	repo, err := store.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	service := cases.NewService(repo)
	incident, _, err := service.CreateIncident(cases.CreateIncidentInput{
		Meta: cases.CommandMeta{RequestID: "create", ActorID: "operator"}, DisplayCaseID: "case-preflight",
		ArtifactID: "artifact-preflight", SensorID: "sensor-preflight", Sensitivity: "low", AbnormalSince: now.Add(-time.Hour),
		TemperatureCelsius: 20, RelativeHumidityPercent: 50, TargetTemperature: store.Range{Min: 18, Max: 22},
		TargetHumidity: store.Range{Min: 45, Max: 55}, SensorStatus: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.PlanPreflight(incident.IncidentID, cases.SubmitPlanInput{
		Meta: cases.CommandMeta{ExpectedRevision: incident.Revision}, Steps: nil,
		TargetTemperature: store.Range{Min: 18, Max: 22}, TargetHumidity: store.Range{Min: 45, Max: 55},
		SafetyEnvelope: &store.SafetyEnvelope{MaxTemperatureChangePerHour: 1, MaxHumidityChangePerHour: 1, MaxExposureMinutes: 30, StopTemperature: store.Range{Min: 10, Max: 30}, StopHumidity: store.Range{Min: 20, Max: 80}, RollbackSteps: []string{"停止"}, RollbackOwnerID: "owner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Passed {
		t.Fatalf("preflight passed a plan that submission must reject: %+v", view)
	}
}
