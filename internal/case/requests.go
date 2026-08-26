package cases

func RequestMatches(left, right CommandMeta) bool {
	return left.RequestID != "" && left.RequestID == right.RequestID
}
