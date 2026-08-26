package store

type Snapshot struct {
	Incidents []EnvironmentIncident
	Audits    []AuditEvent
}

func (s Snapshot) IncidentCount() int { return len(s.Incidents) }
