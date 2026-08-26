package rules

import "time"

func DeadlineAfter(now time.Time, level RiskLevel) time.Time {
	window := 2 * time.Hour
	if level == RiskHigh {
		window = time.Hour
	}
	if level == RiskCritical {
		window = 30 * time.Minute
	}
	return now.Add(window)
}
