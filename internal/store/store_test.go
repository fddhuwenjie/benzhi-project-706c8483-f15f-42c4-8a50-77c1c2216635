package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testIncident() *EnvironmentIncident {
	return &EnvironmentIncident{IncidentID: "inc-1", CaseNumber: "ME-1", OpenedAt: time.Now().UTC(), Status: StatusReported, Readings: []EnvironmentReading{}}
}

func TestStoreRevisionIdempotencyAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	repository, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	created, replayed, err := repository.Create(Mutation{RequestID: "req-create", Operation: "create", IncidentID: "inc-1", ActorID: "a", EventType: "created", Payload: map[string]string{"x": "y"}}, testIncident())
	if err != nil || replayed || created.Revision != 1 {
		t.Fatalf("create = %+v, %v, %v", created, replayed, err)
	}
	updated, replayed, err := repository.Update(Mutation{RequestID: "req-update", Operation: "update", IncidentID: "inc-1", ActorID: "a", ExpectedRevision: 1, EventType: "updated", Payload: struct{}{}}, func(value *EnvironmentIncident) error { value.Status = StatusInspected; return nil })
	if err != nil || replayed || updated.Revision != 2 {
		t.Fatalf("update = %+v, %v, %v", updated, replayed, err)
	}
	replayedValue, replayed, err := repository.Update(Mutation{RequestID: "req-update", Operation: "update", IncidentID: "inc-1", ActorID: "a", ExpectedRevision: 1, EventType: "updated", Payload: struct{}{}}, func(*EnvironmentIncident) error { return errors.New("must not run") })
	if err != nil || !replayed || replayedValue.Revision != 2 {
		t.Fatalf("replay = %+v, %v, %v", replayedValue, replayed, err)
	}
	_, _, err = repository.Update(Mutation{RequestID: "req-conflict", Operation: "update", IncidentID: "inc-1", ExpectedRevision: 1}, func(*EnvironmentIncident) error { return nil })
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("error = %v", err)
	}
	events, err := repository.Timeline("inc-1")
	if err != nil || len(events) != 2 || events[1].PreviousDigest != events[0].EventDigest {
		t.Fatalf("events = %+v, %v", events, err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := reopened.Evidence("inc-1")
	if err != nil || summary.EventCount != 2 {
		t.Fatalf("summary = %+v, %v", summary, err)
	}
}

func TestStoreRejectsAuditTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	repository, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = repository.Create(Mutation{RequestID: "req", Operation: "create", IncidentID: "inc-1", ActorID: "a", EventType: "created", Payload: struct{}{}}, testIncident())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	audits := state["audits"].([]any)
	audits[0].(map[string]any)["actor_id"] = "tampered"
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("tampered audit chain was accepted")
	}
}

func TestRequestIDCannotCrossOperations(t *testing.T) {
	repository, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = repository.Create(Mutation{RequestID: "same", Operation: "create", IncidentID: "inc-1", EventType: "created"}, testIncident())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = repository.Update(Mutation{RequestID: "same", Operation: "different", IncidentID: "inc-1", ExpectedRevision: 1}, func(*EnvironmentIncident) error { return nil })
	if err == nil {
		t.Fatal("cross-operation request_id was accepted")
	}
}

func TestActiveContextIsAtomicAndReleasedWhenSealed(t *testing.T) {
	repository, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := testIncident()
	first.DisplayCaseID, first.SensorID = " Case-A ", " SENSOR-1 "
	created, _, err := repository.Create(Mutation{RequestID: "create-1", Operation: "create", IncidentID: first.IncidentID, EventType: "created"}, first)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := testIncident()
	duplicate.IncidentID, duplicate.CaseNumber = "inc-2", "ME-2"
	duplicate.DisplayCaseID, duplicate.SensorID = "case-a", "sensor-1"
	_, _, err = repository.Create(Mutation{RequestID: "create-2", Operation: "create", IncidentID: duplicate.IncidentID, EventType: "created"}, duplicate)
	var conflict *ActiveIncidentError
	if !errors.As(err, &conflict) || conflict.IncidentID != created.IncidentID || conflict.Revision != 1 {
		t.Fatalf("conflict = %+v, %v", conflict, err)
	}
	_, _, err = repository.Update(Mutation{RequestID: "seal-1", Operation: "seal", IncidentID: first.IncidentID, ExpectedRevision: 1, EventType: "sealed"}, func(value *EnvironmentIncident) error {
		value.Status = StatusSealed
		now := time.Now().UTC()
		value.SealedAt = &now
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = repository.Create(Mutation{RequestID: "create-3", Operation: "create", IncidentID: duplicate.IncidentID, EventType: "created"}, duplicate); err != nil {
		t.Fatalf("create after seal: %v", err)
	}
}

func TestQueryUsesDeadlinePriorityAndCursor(t *testing.T) {
	repository, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	for i, item := range []struct {
		id, risk string
		deadline time.Time
	}{{"overdue", "high", now.Add(-time.Hour)}, {"soon", "moderate", now.Add(30 * time.Minute)}, {"normal", "critical", now.Add(4 * time.Hour)}} {
		incident := testIncident()
		incident.IncidentID = "inc-" + item.id
		incident.CaseNumber = "ME-" + item.id
		incident.DisplayCaseID = "case-" + item.id
		incident.SensorID = "sensor-" + item.id
		incident.RiskLevel = item.risk
		incident.ResponseDeadline = item.deadline
		incident.OpenedAt = now.Add(time.Duration(i) * time.Minute)
		if _, _, err := repository.Create(Mutation{RequestID: "create-" + item.id, Operation: "create", IncidentID: incident.IncidentID, EventType: "created"}, incident); err != nil {
			t.Fatal(err)
		}
	}
	first, err := repository.Query(IncidentQuery{Now: now, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.Items[0].IncidentID != "inc-overdue" || first.NextCursor == "" {
		t.Fatalf("first = %+v", first)
	}
	second, err := repository.Query(IncidentQuery{Now: now, Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].IncidentID != "inc-normal" {
		t.Fatalf("second = %+v", second)
	}
}

func TestSensorHandoverUpdatesActiveIndexAtomically(t *testing.T) {
	repository, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := testIncident()
	first.DisplayCaseID, first.SensorID = "case-a", "sensor-old"
	if _, _, err = repository.Create(Mutation{RequestID: "create-first", Operation: "create", IncidentID: first.IncidentID, EventType: "created"}, first); err != nil {
		t.Fatal(err)
	}
	second := testIncident()
	second.IncidentID, second.CaseNumber = "inc-2", "ME-2"
	second.DisplayCaseID, second.SensorID = "case-a", "sensor-used"
	if _, _, err = repository.Create(Mutation{RequestID: "create-second", Operation: "create", IncidentID: second.IncidentID, EventType: "created"}, second); err != nil {
		t.Fatal(err)
	}
	_, _, err = repository.Update(Mutation{RequestID: "handover-conflict", Operation: "handover", IncidentID: first.IncidentID, ExpectedRevision: 1, EventType: "sensor.handed_over"}, func(value *EnvironmentIncident) error {
		value.SensorID = "sensor-used"
		return nil
	})
	var conflict *ActiveIncidentError
	if !errors.As(err, &conflict) || conflict.IncidentID != second.IncidentID {
		t.Fatalf("conflict = %+v, err = %v", conflict, err)
	}
	unchanged, err := repository.Get(first.IncidentID)
	if err != nil || unchanged.SensorID != "sensor-old" || unchanged.Revision != 1 {
		t.Fatalf("unchanged = %+v, err = %v", unchanged, err)
	}
	if events, err := repository.Timeline(first.IncidentID); err != nil || len(events) != 1 {
		t.Fatalf("events = %+v, err = %v", events, err)
	}
}
