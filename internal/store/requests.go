package store

type RequestRecord struct {
	RequestID  string
	IncidentID string
	Revision   int64
	Response   []byte
}
