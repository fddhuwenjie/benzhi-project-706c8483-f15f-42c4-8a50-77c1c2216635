package timelinedetailscachealias

import (
	"path/filepath"
	"testing"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

func TestTimelineResultCannotPoisonCachedAuditDetails(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	incident := &store.EnvironmentIncident{
		IncidentID:    "inc-timeline-cache",
		CaseNumber:    "ME-TIMELINE-CACHE",
		DisplayCaseID: "case-timeline-cache",
		SensorID:      "sensor-timeline-cache",
		Status:        store.StatusReported,
	}
	_, _, err = repository.Create(store.Mutation{
		RequestID:  "create-timeline-cache",
		Operation:  "create_incident",
		IncidentID: incident.IncidentID,
		ActorID:    "operator-1",
		EventType:  "incident.reported",
		Payload:    map[string]string{"source": "sensor"},
	}, incident)
	if err != nil {
		t.Fatal(err)
	}

	service := cases.NewService(repository)
	first, err := service.TimelinePage(incident.IncidentID, cases.TimelineQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 1 || first.Events[0].Details["event_label"] != "异常登记" {
		t.Fatalf("unexpected first timeline: %+v", first)
	}
	first.Events[0].Details["event_label"] = "调用方篡改的标签"
	first.Events[0].Details["risk_explanation"] = "调用方伪造的审计说明"

	second, err := service.TimelinePage(incident.IncidentID, cases.TimelineQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Events[0].Details["event_label"] != "异常登记" {
		t.Fatalf("cached audit details were poisoned: %+v", second.Events[0].Details)
	}
	if second.Events[0].Details["risk_explanation"] == "调用方伪造的审计说明" {
		t.Fatalf("forged audit explanation crossed the cache boundary: %+v", second.Events[0].Details)
	}
}
