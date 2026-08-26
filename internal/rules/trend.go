package rules

func TrendDirection(slope float64) string {
	if slope > 0.01 {
		return "rising"
	}
	if slope < -0.01 {
		return "falling"
	}
	return "stable"
}
