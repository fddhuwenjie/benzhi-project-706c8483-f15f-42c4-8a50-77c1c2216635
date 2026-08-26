package httpapi

func HeaderValue(headers map[string]string, key string) string { return headers[key] }
