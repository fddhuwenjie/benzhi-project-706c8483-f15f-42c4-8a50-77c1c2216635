package cases

func ClampPageSize(size int) int {
	if size < 1 {
		return 1
	}
	if size > 100 {
		return 100
	}
	return size
}
