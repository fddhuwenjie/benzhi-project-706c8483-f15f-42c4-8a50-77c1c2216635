package cases

import "museumenv/internal/store"

func AuditForIncident(events []store.AuditEvent, incidentID string) []store.AuditEvent {
	result := make([]store.AuditEvent, 0, len(events))
	for _, event := range events {
		if event.IncidentID == incidentID {
			result = append(result, event)
		}
	}
	return result
}
