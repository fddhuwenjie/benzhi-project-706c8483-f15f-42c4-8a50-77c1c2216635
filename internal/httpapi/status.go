package httpapi

func IsSuccess(status int) bool { return status >= 200 && status < 300 }
