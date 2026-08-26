package rules

import (
	"fmt"
	"math"
	"strings"
	"time"
)

type Sensitivity string

const (
	SensitivityLow    Sensitivity = "low"
	SensitivityMedium Sensitivity = "medium"
	SensitivityHigh   Sensitivity = "high"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskModerate RiskLevel = "moderate"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Range struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

func (r Range) Valid() bool             { return r.Min < r.Max }
func (r Range) Contains(v float64) bool { return v >= r.Min && v <= r.Max }

type RiskInput struct {
	Temperature       float64
	Humidity          float64
	TargetTemperature Range
	TargetHumidity    Range
	Duration          time.Duration
	Sensitivity       Sensitivity
}

type RiskAssessment struct {
	Level           RiskLevel     `json:"level"`
	ResponseWithin  time.Duration `json:"-"`
	ResponseMinutes int64         `json:"response_minutes"`
	Score           int           `json:"score"`
	Reasons         []string      `json:"reasons"`
}

func AssessRisk(in RiskInput) (RiskAssessment, error) {
	if !in.TargetTemperature.Valid() || !in.TargetHumidity.Valid() {
		return RiskAssessment{}, fmt.Errorf("目标温湿度范围无效")
	}
	if in.Duration < 0 {
		return RiskAssessment{}, fmt.Errorf("异常持续时间不能为负数")
	}
	if in.Sensitivity != SensitivityLow && in.Sensitivity != SensitivityMedium && in.Sensitivity != SensitivityHigh {
		return RiskAssessment{}, fmt.Errorf("不支持的展品敏感等级")
	}
	tempDeviation := deviation(in.Temperature, in.TargetTemperature)
	humidityDeviation := deviation(in.Humidity, in.TargetHumidity)
	score := 0
	reasons := make([]string, 0, 3)
	if tempDeviation > 0 {
		points := severityPoints(tempDeviation, 2, 5)
		score += points
		reasons = append(reasons, fmt.Sprintf("温度偏离目标范围 %.1f 摄氏度", tempDeviation))
	}
	if humidityDeviation > 0 {
		points := severityPoints(humidityDeviation, 5, 15)
		score += points
		reasons = append(reasons, fmt.Sprintf("相对湿度偏离目标范围 %.1f 个百分点", humidityDeviation))
	}
	if in.Duration >= 24*time.Hour {
		score += 3
		reasons = append(reasons, "异常持续时间达到 24 小时")
	} else if in.Duration >= 4*time.Hour {
		score += 2
		reasons = append(reasons, "异常持续时间达到 4 小时")
	} else if in.Duration >= time.Hour {
		score++
		reasons = append(reasons, "异常持续时间达到 1 小时")
	}
	if in.Sensitivity == SensitivityHigh {
		score += 3
		reasons = append(reasons, "展品为高敏感等级")
	} else if in.Sensitivity == SensitivityMedium {
		score++
		reasons = append(reasons, "展品为中敏感等级")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "读数处于目标范围且未发现附加风险")
	}
	assessment := RiskAssessment{Score: score, Reasons: reasons}
	switch {
	case score >= 9:
		assessment.Level, assessment.ResponseWithin = RiskCritical, 30*time.Minute
	case score >= 6:
		assessment.Level, assessment.ResponseWithin = RiskHigh, 2*time.Hour
	case score >= 3:
		assessment.Level, assessment.ResponseWithin = RiskModerate, 8*time.Hour
	default:
		assessment.Level, assessment.ResponseWithin = RiskLow, 24*time.Hour
	}
	assessment.ResponseMinutes = int64(assessment.ResponseWithin / time.Minute)
	return assessment, nil
}

func deviation(value float64, target Range) float64 {
	if value < target.Min {
		return target.Min - value
	}
	if value > target.Max {
		return value - target.Max
	}
	return 0
}

func severityPoints(value, warning, severe float64) int {
	if value >= severe {
		return 4
	}
	if value >= warning {
		return 2
	}
	return 1
}

type PlanInput struct {
	Steps             []string
	TemperatureTarget Range
	HumidityTarget    Range
	IsolationRequired bool
	IsolationRecorded bool
	RiskLevel         RiskLevel
}

func ValidatePlan(in PlanInput) []string {
	var failures []string
	if len(in.Steps) == 0 {
		failures = append(failures, "干预方案至少需要一个执行步骤")
	}
	for i, step := range in.Steps {
		if strings.TrimSpace(step) == "" {
			failures = append(failures, fmt.Sprintf("第 %d 个执行步骤为空", i+1))
		}
	}
	if !in.TemperatureTarget.Valid() {
		failures = append(failures, "目标温度范围无效")
	}
	if !in.HumidityTarget.Valid() {
		failures = append(failures, "目标湿度范围无效")
	}
	if in.TemperatureTarget.Valid() && (in.TemperatureTarget.Min < 5 || in.TemperatureTarget.Max > 35) {
		failures = append(failures, "目标温度超出 5 至 35 摄氏度安全边界")
	}
	if in.HumidityTarget.Valid() && (in.HumidityTarget.Min < 20 || in.HumidityTarget.Max > 75) {
		failures = append(failures, "目标湿度超出 20% 至 75% 安全边界")
	}
	if (in.RiskLevel == RiskHigh || in.RiskLevel == RiskCritical || in.IsolationRequired) && !in.IsolationRecorded {
		failures = append(failures, "高风险或要求隔离的方案必须先记录临时隔离措施")
	}
	return failures
}

func NearlyEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}
