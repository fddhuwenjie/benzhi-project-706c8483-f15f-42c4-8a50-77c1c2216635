package expirecommitmentstate

import (
	"path/filepath"
	"testing"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

func TestExpireCommitmentRefreshesEscalationState(t *testing.T) {
	repo, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	incident := &store.EnvironmentIncident{
		IncidentID: "inc-expire", CaseNumber: "ME-expire", Status: store.StatusReported,
		OpenedAt: now.Add(-time.Hour), ResponseDeadline: now.Add(-30 * time.Minute), RiskLevel: "low",
		EscalationStatus: store.EscalationOverdueAcknowledged, RemainingMinutes: -30, CommitmentOwnerID: "owner-1",
		DeadlineCommitments: []store.DeadlineCommitment{{CommitmentID: "commit-1", CommitmentDueAt: now.Add(-time.Minute), Status: "effective", OwnerID: "owner-1"}},
	}
	if _, _, err := repo.Create(store.Mutation{RequestID: "create", Operation: "create", IncidentID: incident.IncidentID, EventType: "incident.reported"}, incident); err != nil {
		t.Fatal(err)
	}
	got, _, err := cases.NewService(repo).ExpireCommitment(incident.IncidentID, "commit-1", cases.ExpireInput{Meta: cases.CommandMeta{RequestID: "expire", ActorID: "supervisor", ExpectedRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if got.EscalationStatus != store.EscalationOverdueUnacknowledged {
		t.Fatalf("escalation status stayed stale after expiration: %s", got.EscalationStatus)
	}
	if got.CommitmentOwnerID != "" {
		t.Fatalf("commitment owner not cleared: %q", got.CommitmentOwnerID)
	}
}
