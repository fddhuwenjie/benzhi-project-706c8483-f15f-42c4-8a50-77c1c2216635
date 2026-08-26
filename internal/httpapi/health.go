package httpapi

type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}
