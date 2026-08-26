package store

type QueryOptions struct {
	Status Status
	Limit  int
	Offset int
}

func (q QueryOptions) NormalizedLimit() int {
	if q.Limit <= 0 || q.Limit > 100 {
		return 100
	}
	return q.Limit
}
