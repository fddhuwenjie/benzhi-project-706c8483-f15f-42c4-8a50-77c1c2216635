package evidencecache

import (
	"path/filepath"
	"testing"
	"time"

	"museumenv/internal/store"
)

func TestEvidenceSummaryRefreshesAfterIncidentUpdate(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	incident := &store.EnvironmentIncident{
		IncidentID:       "inc-evidence-cache",
		CaseNumber:       "ME-EVIDENCE-CACHE",
		DisplayCaseID:    "case-evidence-cache",
		ArtifactID:       "artifact-evidence-cache",
		SensorID:         "sensor-evidence-cache",
		OpenedAt:         now,
		AbnormalSince:    now.Add(-time.Hour),
		ResponseDeadline: now.Add(time.Hour),
		Status:           store.StatusReported,
		CreatedBy:        "operator-1",
	}
	if _, _, err := repository.Create(store.Mutation{
		RequestID:  "create-evidence-cache",
		Operation:  "create_incident",
		IncidentID: incident.IncidentID,
		ActorID:    "operator-1",
		EventType:  "incident.reported",
		Payload:    map[string]string{"source": "private-repro"},
	}, incident); err != nil {
		t.Fatal(err)
	}
	first, err := repository.Evidence(incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if first.EventCount != 1 || first.LatestDigest == "" {
		t.Fatalf("initial evidence = %+v", first)
	}
	if _, _, err := repository.Update(store.Mutation{
		RequestID:        "update-evidence-cache",
		Operation:        "record_inspection",
		IncidentID:       incident.IncidentID,
		ActorID:          "inspector-1",
		ExpectedRevision: 1,
		EventType:        "inspection.recorded",
		Payload:          map[string]string{"finding": "new evidence"},
	}, func(value *store.EnvironmentIncident) error {
		value.Status = store.StatusInspected
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	second, err := repository.Evidence(incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if second.EventCount != 2 || second.LatestDigest == first.LatestDigest || second.Status != "unsealed" {
		t.Fatalf("stale evidence after update: first=%+v second=%+v", first, second)
	}
}
