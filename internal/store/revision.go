package store

func NextRevision(current int64) int64 {
	if current < 0 {
		return 1
	}
	return current + 1
}
