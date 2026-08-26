package rules

func ExplainRisk(level RiskLevel, score float64) string {
	return "风险级别 " + string(level) + "，评分 " + formatScore(score)
}

func formatScore(score float64) string {
	return strconvFormat(score)
}
