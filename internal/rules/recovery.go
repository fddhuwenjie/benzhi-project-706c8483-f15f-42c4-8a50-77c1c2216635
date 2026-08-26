package rules

import (
	"fmt"
	"sort"
	"time"
)

type RecoveryReading struct {
	CapturedAt  time.Time
	Temperature float64
	Humidity    float64
	SensorOK    bool
}

type RecoveryPolicy struct {
	TemperatureTarget     Range
	HumidityTarget        Range
	MinimumStableDuration time.Duration
	MinimumReadings       int
	MaximumGap            time.Duration
}

type RecoveryResult struct {
	Qualified      bool          `json:"qualified"`
	StableDuration time.Duration `json:"-"`
	StableMinutes  int64         `json:"stable_minutes"`
	Failures       []string      `json:"failures"`
}

func EvaluateRecovery(readings []RecoveryReading, policy RecoveryPolicy) RecoveryResult {
	result := RecoveryResult{}
	if !policy.TemperatureTarget.Valid() || !policy.HumidityTarget.Valid() {
		result.Failures = append(result.Failures, "恢复目标范围无效")
		return result
	}
	if policy.MinimumReadings < 2 {
		policy.MinimumReadings = 2
	}
	if policy.MinimumStableDuration <= 0 {
		policy.MinimumStableDuration = 30 * time.Minute
	}
	if policy.MaximumGap <= 0 {
		policy.MaximumGap = 2 * time.Hour
	}
	if len(readings) < policy.MinimumReadings {
		result.Failures = append(result.Failures, fmt.Sprintf("观察读数不足，需要至少 %d 条", policy.MinimumReadings))
		return result
	}
	ordered := append([]RecoveryReading(nil), readings...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].CapturedAt.Before(ordered[j].CapturedAt) })
	for i, reading := range ordered {
		if !reading.SensorOK {
			result.Failures = append(result.Failures, fmt.Sprintf("第 %d 条读数的传感器状态无效", i+1))
		}
		if !policy.TemperatureTarget.Contains(reading.Temperature) {
			result.Failures = append(result.Failures, fmt.Sprintf("第 %d 条温度读数 %.1f 不在目标范围", i+1, reading.Temperature))
		}
		if !policy.HumidityTarget.Contains(reading.Humidity) {
			result.Failures = append(result.Failures, fmt.Sprintf("第 %d 条湿度读数 %.1f 不在目标范围", i+1, reading.Humidity))
		}
		if i > 0 {
			gap := reading.CapturedAt.Sub(ordered[i-1].CapturedAt)
			if gap <= 0 {
				result.Failures = append(result.Failures, "观察读数时间必须严格递增")
			}
			if gap > policy.MaximumGap {
				result.Failures = append(result.Failures, fmt.Sprintf("观察读数间隔 %s 超过允许上限", gap))
			}
		}
	}
	result.StableDuration = ordered[len(ordered)-1].CapturedAt.Sub(ordered[0].CapturedAt)
	result.StableMinutes = int64(result.StableDuration / time.Minute)
	if result.StableDuration < policy.MinimumStableDuration {
		result.Failures = append(result.Failures, fmt.Sprintf("稳定观察时长不足，需要至少 %s", policy.MinimumStableDuration))
	}
	result.Qualified = len(result.Failures) == 0
	return result
}

type ReopenGate struct {
	ReviewApproved    bool
	ExecutionRecorded bool
	RecoveryQualified bool
	SupervisorRole    bool
	AlreadySealed     bool
}

func CheckReopenGate(gate ReopenGate) []string {
	var failures []string
	if !gate.ReviewApproved {
		failures = append(failures, "干预方案尚未审核通过")
	}
	if !gate.ExecutionRecorded {
		failures = append(failures, "尚未登记干预执行证据")
	}
	if !gate.RecoveryQualified {
		failures = append(failures, "恢复观察尚未通过验证")
	}
	if !gate.SupervisorRole {
		failures = append(failures, "仅值班主管可以签署重新开放")
	}
	if gate.AlreadySealed {
		failures = append(failures, "事件已经封存")
	}
	return failures
}

type EvidenceGate struct {
	RegistrationReadings  int
	Inspections           int
	PlanVersions          int
	PlanReviews           int
	Executions            int
	ObservationWindows    int
	ObservationReadings   int
	Verifications         int
	QualifiedVerification bool
}

func CheckEvidenceGate(gate EvidenceGate) []string {
	var failures []string
	if gate.RegistrationReadings < 1 {
		failures = append(failures, "缺少异常登记读数")
	}
	if gate.Inspections < 1 {
		failures = append(failures, "缺少现场复核证据")
	}
	if gate.PlanVersions < 1 {
		failures = append(failures, "缺少干预方案版本")
	}
	if gate.PlanReviews < 1 {
		failures = append(failures, "缺少方案审核决定")
	}
	if gate.Executions < 1 {
		failures = append(failures, "缺少干预执行记录")
	}
	if gate.ObservationWindows < 1 || gate.ObservationReadings < 1 {
		failures = append(failures, "缺少恢复观察窗口或读数")
	}
	if gate.Verifications < 1 {
		failures = append(failures, "缺少恢复验证结论")
	}
	if !gate.QualifiedVerification {
		failures = append(failures, "缺少当前观察窗口的合格验证")
	}
	return failures
}
