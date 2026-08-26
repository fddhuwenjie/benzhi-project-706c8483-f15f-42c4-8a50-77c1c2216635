package rules

type NumericRange struct {
	Min float64
	Max float64
}

func (r NumericRange) Contains(value float64) bool {
	return value >= r.Min && value <= r.Max
}

func (r NumericRange) Valid() bool { return r.Min <= r.Max }
