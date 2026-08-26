package rules

func IsEscalated(level RiskLevel) bool {
	return level == RiskHigh || level == RiskCritical
}
