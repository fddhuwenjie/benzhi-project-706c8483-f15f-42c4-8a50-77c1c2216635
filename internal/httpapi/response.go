package httpapi

type ResponseMeta struct {
	RequestID string `json:"request_id,omitempty"`
	Revision  int64  `json:"revision,omitempty"`
}
