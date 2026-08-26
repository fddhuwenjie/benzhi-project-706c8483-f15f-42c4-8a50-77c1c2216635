package httpapi

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
