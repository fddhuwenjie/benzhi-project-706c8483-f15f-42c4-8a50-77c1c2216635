package rules

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type DiscoveryReading struct {
	ID           string
	CapturedAt   time.Time
	Temperature  float64
	Humidity     float64
	Quality      string
	SensorStatus string
}

type BatchRiskAssessment struct {
	RiskAssessment
	PeakReadingID string
	Explanation   string
	TrendSlope    float64
}

func AssessDiscoveryBatch(readings []DiscoveryReading, targetTemperature, targetHumidity Range, abnormalSince, evaluatedAt time.Time, sensitivity Sensitivity) (BatchRiskAssessment, error) {
	if len(readings) == 0 {
		return BatchRiskAssessment{}, fmt.Errorf("发现阶段读数不能为空")
	}
	var highest RiskAssessment
	peakID := ""
	for _, reading := range readings {
		if strings.EqualFold(reading.Quality, "warning") || strings.EqualFold(reading.Quality, "low") {
			continue
		}
		assessment, err := AssessRisk(RiskInput{Temperature: reading.Temperature, Humidity: reading.Humidity, TargetTemperature: targetTemperature, TargetHumidity: targetHumidity, Duration: evaluatedAt.Sub(abnormalSince), Sensitivity: sensitivity})
		if err != nil {
			return BatchRiskAssessment{}, err
		}
		if peakID == "" || RiskRank(assessment.Level) > RiskRank(highest.Level) || assessment.Score > highest.Score {
			highest, peakID = assessment, reading.ID
		}
	}
	if peakID == "" {
		// Keep an original warning-only batch observable, but assign the first
		// point as evidence without treating it as a quality-approved peak.
		first := readings[0]
		highest, _ = AssessRisk(RiskInput{Temperature: first.Temperature, Humidity: first.Humidity, TargetTemperature: targetTemperature, TargetHumidity: targetHumidity, Duration: evaluatedAt.Sub(abnormalSince), Sensitivity: sensitivity})
		peakID = first.ID
	}
	slope := 0.0
	if len(readings) > 1 {
		first, last := readings[0], readings[len(readings)-1]
		minutes := last.CapturedAt.Sub(first.CapturedAt).Minutes()
		if minutes > 0 {
			slope = (deviation(last.Temperature, targetTemperature) + deviation(last.Humidity, targetHumidity) - deviation(first.Temperature, targetTemperature) - deviation(first.Humidity, targetHumidity)) / minutes
		}
	}
	return BatchRiskAssessment{RiskAssessment: highest, PeakReadingID: peakID, TrendSlope: slope, Explanation: fmt.Sprintf("批次逐点评估后由读数 %s 触发最高风险 %s（评分 %d），已合并温湿度峰值偏差、异常持续时间和展品敏感等级", peakID, highest.Level, highest.Score)}, nil
}

type EscalationAssessment struct {
	Status           string        `json:"status"`
	RemainingMinutes int64         `json:"remaining_minutes"`
	MaximumRemedy    time.Duration `json:"-"`
}

func MaximumRemedyWindow(level RiskLevel) time.Duration {
	switch level {
	case RiskCritical:
		return 2 * time.Hour
	case RiskHigh:
		return 4 * time.Hour
	case RiskModerate:
		return 12 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func AssessEscalation(deadline, now time.Time, sealed, hasEffectiveCommitment bool) EscalationAssessment {
	remaining := int64(math.Ceil(deadline.Sub(now).Minutes()))
	if sealed {
		return EscalationAssessment{Status: "archived", RemainingMinutes: remaining}
	}
	if !deadline.After(now) {
		status := "overdue_unacknowledged"
		if hasEffectiveCommitment {
			status = "overdue_acknowledged"
		}
		return EscalationAssessment{Status: status, RemainingMinutes: remaining}
	}
	if deadline.Sub(now) <= time.Hour {
		return EscalationAssessment{Status: "due_soon", RemainingMinutes: remaining}
	}
	return EscalationAssessment{Status: "normal", RemainingMinutes: remaining}
}

type SafetyEnvelopeInput struct {
	MaxTemperatureChangePerHour float64
	MaxHumidityChangePerHour    float64
	MaxExposureMinutes          int64
	StopTemperature             Range
	StopHumidity                Range
	RollbackSteps               []string
	RollbackOwnerID             string
}

func SafetyLimits(sensitivity Sensitivity, risk RiskLevel) (float64, float64, int64) {
	temp, humidity, exposure := 4.0, 10.0, int64(240)
	if sensitivity == SensitivityHigh {
		temp, humidity, exposure = 1.0, 3.0, 60
	} else if sensitivity == SensitivityMedium {
		temp, humidity, exposure = 2.0, 5.0, 120
	}
	if risk == RiskCritical {
		exposure /= 2
	} else if risk == RiskHigh {
		exposure = exposure * 3 / 4
	}
	return temp, humidity, exposure
}

func ValidateSafetyEnvelope(in SafetyEnvelopeInput, sensitivity Sensitivity, risk RiskLevel) []string {
	var failures []string
	maxTemperature, maxHumidity, maxExposure := SafetyLimits(sensitivity, risk)
	if in.MaxTemperatureChangePerHour <= 0 || in.MaxTemperatureChangePerHour > maxTemperature {
		failures = append(failures, fmt.Sprintf("每小时最大温度变化 %.2f 超过允许值 %.2f", in.MaxTemperatureChangePerHour, maxTemperature))
	}
	if in.MaxHumidityChangePerHour <= 0 || in.MaxHumidityChangePerHour > maxHumidity {
		failures = append(failures, fmt.Sprintf("每小时最大湿度变化 %.2f 超过允许值 %.2f", in.MaxHumidityChangePerHour, maxHumidity))
	}
	if in.MaxExposureMinutes <= 0 || in.MaxExposureMinutes > maxExposure {
		failures = append(failures, fmt.Sprintf("允许暴露时长 %d 分钟超过上限 %d 分钟", in.MaxExposureMinutes, maxExposure))
	}
	if !in.StopTemperature.Valid() || in.StopTemperature.Min <= -20 || in.StopTemperature.Max >= 60 {
		failures = append(failures, "温度停止阈值必须严格位于物理安全边界内")
	}
	if !in.StopHumidity.Valid() || in.StopHumidity.Min <= 0 || in.StopHumidity.Max >= 100 {
		failures = append(failures, "湿度停止阈值必须严格位于物理安全边界内")
	}
	if len(in.RollbackSteps) == 0 || strings.TrimSpace(in.RollbackOwnerID) == "" {
		failures = append(failures, "回退步骤及对应责任人不能为空")
	}
	for _, step := range in.RollbackSteps {
		if strings.TrimSpace(step) == "" {
			failures = append(failures, "回退步骤不能为空")
			break
		}
	}
	return failures
}

type EnvelopeActual struct {
	DurationMinutes   int64
	TemperatureBefore float64
	TemperatureAfter  float64
	HumidityBefore    float64
	HumidityAfter     float64
}

func CheckEnvelopeExecution(envelope SafetyEnvelopeInput, actual EnvelopeActual) []string {
	var failures []string
	if actual.DurationMinutes <= 0 {
		return []string{"执行持续时间必须大于零"}
	}
	hours := float64(actual.DurationMinutes) / 60
	temperatureRate := math.Abs(actual.TemperatureAfter-actual.TemperatureBefore) / hours
	humidityRate := math.Abs(actual.HumidityAfter-actual.HumidityBefore) / hours
	if temperatureRate > envelope.MaxTemperatureChangePerHour {
		failures = append(failures, fmt.Sprintf("参数 temperature_change_per_hour 越界：允许值 %.2f，实际值 %.2f", envelope.MaxTemperatureChangePerHour, temperatureRate))
	}
	if humidityRate > envelope.MaxHumidityChangePerHour {
		failures = append(failures, fmt.Sprintf("参数 humidity_change_per_hour 越界：允许值 %.2f，实际值 %.2f", envelope.MaxHumidityChangePerHour, humidityRate))
	}
	if actual.DurationMinutes > envelope.MaxExposureMinutes {
		failures = append(failures, fmt.Sprintf("参数 exposure_minutes 越界：允许值 %d，实际值 %d", envelope.MaxExposureMinutes, actual.DurationMinutes))
	}
	if !envelope.StopTemperature.Contains(actual.TemperatureAfter) {
		failures = append(failures, fmt.Sprintf("参数 stop_temperature 越界：允许值 %.1f 至 %.1f，实际值 %.1f", envelope.StopTemperature.Min, envelope.StopTemperature.Max, actual.TemperatureAfter))
	}
	if !envelope.StopHumidity.Contains(actual.HumidityAfter) {
		failures = append(failures, fmt.Sprintf("参数 stop_humidity 越界：允许值 %.1f 至 %.1f，实际值 %.1f", envelope.StopHumidity.Min, envelope.StopHumidity.Max, actual.HumidityAfter))
	}
	return failures
}

type DeviationInput struct {
	Type           string
	PlanStepNumber int
}

func ClassifyDeviation(in DeviationInput, planSteps []string) (string, error) {
	if in.PlanStepNumber < 1 || in.PlanStepNumber > len(planSteps) {
		return "", fmt.Errorf("偏差关联的方案步骤不存在")
	}
	if in.Type != "material_substitution" && in.Type != "step_reorder" && in.Type != "parameter_deviation" {
		return "", fmt.Errorf("偏差 type 必须为 material_substitution、step_reorder 或 parameter_deviation")
	}
	if IsSafetyCriticalStep(planSteps[in.PlanStepNumber-1]) && in.Type != "material_substitution" {
		return "rejected", fmt.Errorf("安全关键步骤缺失或改序不得登记为可复核偏差")
	}
	if in.Type == "step_reorder" {
		return "record_only", nil
	}
	return "review_required", nil
}

func ValidateSensorOverlap(oldPoints, newPoints []DiscoveryReading, reference string) []string {
	var failures []string
	if strings.TrimSpace(reference) == "" {
		failures = append(failures, "校准参考不能为空")
	}
	if len(oldPoints) == 0 || len(oldPoints) != len(newPoints) {
		return append(failures, "新旧传感器必须提交数量相同的重叠读数")
	}
	for i := range oldPoints {
		if !oldPoints[i].CapturedAt.Equal(newPoints[i].CapturedAt) {
			failures = append(failures, fmt.Sprintf("第 %d 组新旧读数采集时间必须相同", i+1))
		}
		comparison := CompareReadings(oldPoints[i].Temperature, oldPoints[i].Humidity, newPoints[i].Temperature, newPoints[i].Humidity)
		if !comparison.Trustworthy {
			failures = append(failures, fmt.Sprintf("第 %d 组重叠读数差值超限：温度 %.1f、湿度 %.1f", i+1, comparison.TemperatureDifference, comparison.HumidityDifference))
		}
		if i > 0 && !oldPoints[i].CapturedAt.After(oldPoints[i-1].CapturedAt) {
			failures = append(failures, "重叠读数采集时间必须严格递增")
		}
	}
	return failures
}

func PolicyFor(risk RiskLevel, sensitivity Sensitivity, temperatureTarget, humidityTarget Range) RecoveryPolicy {
	minutes, readings := int64(30), 3
	if risk == RiskCritical || sensitivity == SensitivityHigh {
		minutes, readings = 60, 5
	} else if risk == RiskHigh || sensitivity == SensitivityMedium {
		minutes, readings = 45, 4
	}
	return RecoveryPolicy{TemperatureTarget: temperatureTarget, HumidityTarget: humidityTarget, MinimumStableDuration: time.Duration(minutes) * time.Minute, MinimumReadings: readings, MaximumGap: MaximumObservationGap(risk)}
}

type RecoveryProgress struct {
	PolicyVersion          string     `json:"policy_version"`
	StableMinutes          int64      `json:"stable_minutes"`
	ValidReadings          int        `json:"valid_readings"`
	RemainingMinutes       int64      `json:"remaining_minutes"`
	RemainingReadings      int        `json:"remaining_readings"`
	LatestInterruption     string     `json:"latest_interruption,omitempty"`
	EarliestVerificationAt *time.Time `json:"earliest_verification_at,omitempty"`
	SegmentStartedAt       *time.Time `json:"segment_started_at,omitempty"`
	SegmentEndedAt         *time.Time `json:"segment_ended_at,omitempty"`
	Qualified              bool       `json:"qualified"`
}

func CalculateRecoveryProgress(readings []RecoveryReading, policy RecoveryPolicy, version string) RecoveryProgress {
	progress := RecoveryProgress{PolicyVersion: version}
	ordered := append([]RecoveryReading(nil), readings...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].CapturedAt.Before(ordered[j].CapturedAt) })
	var segment []RecoveryReading
	for _, reading := range ordered {
		reason := ""
		if !reading.SensorOK {
			reason = "warning 读数中断连续区段"
		} else if !policy.TemperatureTarget.Contains(reading.Temperature) || !policy.HumidityTarget.Contains(reading.Humidity) {
			reason = "阈值超限中断连续区段"
		} else if len(segment) > 0 && reading.CapturedAt.Sub(segment[len(segment)-1].CapturedAt) > policy.MaximumGap {
			reason = "采样间隔过长中断连续区段"
		}
		if reason != "" {
			progress.LatestInterruption = reason
			segment = nil
			if reading.SensorOK && policy.TemperatureTarget.Contains(reading.Temperature) && policy.HumidityTarget.Contains(reading.Humidity) {
				segment = append(segment, reading)
			}
			continue
		}
		segment = append(segment, reading)
	}
	progress.ValidReadings = len(segment)
	if len(segment) > 0 {
		start, end := segment[0].CapturedAt, segment[len(segment)-1].CapturedAt
		progress.SegmentStartedAt, progress.SegmentEndedAt = &start, &end
		progress.StableMinutes = int64(end.Sub(start) / time.Minute)
		earliest := start.Add(policy.MinimumStableDuration)
		progress.EarliestVerificationAt = &earliest
	}
	minimumMinutes := int64(policy.MinimumStableDuration / time.Minute)
	progress.RemainingMinutes = minimumMinutes - progress.StableMinutes
	if progress.RemainingMinutes < 0 {
		progress.RemainingMinutes = 0
	}
	progress.RemainingReadings = policy.MinimumReadings - progress.ValidReadings
	if progress.RemainingReadings < 0 {
		progress.RemainingReadings = 0
	}
	progress.Qualified = progress.RemainingMinutes == 0 && progress.RemainingReadings == 0
	return progress
}

type ReadinessItem struct {
	Code    string `json:"code"`
	Ready   bool   `json:"ready"`
	Message string `json:"message"`
}

func Readiness(items []ReadinessItem) (bool, []ReadinessItem) {
	ready := true
	for _, item := range items {
		if !item.Ready {
			ready = false
		}
	}
	return ready, items
}
