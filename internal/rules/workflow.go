package rules

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type DeadlineAssessment struct {
	RemainingMinutes int64
	Status           string
}

func AssessDeadline(deadline, now time.Time, sealed bool) DeadlineAssessment {
	remaining := int64(math.Ceil(deadline.Sub(now).Minutes()))
	if sealed {
		return DeadlineAssessment{RemainingMinutes: remaining, Status: "archived"}
	}
	if !deadline.After(now) {
		return DeadlineAssessment{RemainingMinutes: remaining, Status: "overdue"}
	}
	if deadline.Sub(now) <= 60*time.Minute {
		return DeadlineAssessment{RemainingMinutes: remaining, Status: "due_soon"}
	}
	return DeadlineAssessment{RemainingMinutes: remaining, Status: "normal"}
}

func RiskRank(level RiskLevel) int {
	switch level {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskModerate:
		return 2
	case RiskLow:
		return 1
	}
	return 0
}

func MaximumObservationGap(level RiskLevel) time.Duration {
	switch level {
	case RiskCritical:
		return 15 * time.Minute
	case RiskHigh:
		return 30 * time.Minute
	case RiskModerate:
		return time.Hour
	default:
		return 2 * time.Hour
	}
}

type ReadingComparison struct {
	TemperatureDifference, HumidityDifference float64
	Trustworthy                               bool
}

func CompareReadings(sensorTemperature, sensorHumidity, fieldTemperature, fieldHumidity float64) ReadingComparison {
	result := ReadingComparison{TemperatureDifference: math.Abs(fieldTemperature - sensorTemperature), HumidityDifference: math.Abs(fieldHumidity - sensorHumidity)}
	result.Trustworthy = result.TemperatureDifference <= 2 && result.HumidityDifference <= 5
	return result
}

type ExecutionStep struct {
	Number                  int
	Result, DeviationReason string
}
type ExecutionMaterial struct {
	Name, Batch     string
	QuantityPresent bool
	ExpiresAt       time.Time
}
type ExecutionCheck struct {
	PlanSteps                           []string
	Steps                               []ExecutionStep
	Materials                           []ExecutionMaterial
	ExecutedAt                          time.Time
	BeforeAt, AfterAt                   time.Time
	BeforeTemperature, AfterTemperature float64
	BeforeHumidity, AfterHumidity       float64
	BeforeReference, AfterReference     string
}

func IsSafetyCriticalStep(step string) bool {
	return strings.Contains(step, "隔离") || strings.Contains(step, "传感器保护")
}

func CheckExecution(in ExecutionCheck) []string {
	var failures []string
	seenSteps := map[int]bool{}
	last := 0
	for _, item := range in.Steps {
		if item.Number < 1 || item.Number > len(in.PlanSteps) {
			failures = append(failures, fmt.Sprintf("方案步骤编号 %d 不存在", item.Number))
			continue
		}
		if seenSteps[item.Number] {
			failures = append(failures, fmt.Sprintf("方案步骤 %d 重复登记", item.Number))
			continue
		}
		seenSteps[item.Number] = true
		if item.Number < last {
			failures = append(failures, "方案步骤执行顺序冲突")
		}
		last = item.Number
		if item.Result != "completed" && item.Result != "skipped" {
			failures = append(failures, fmt.Sprintf("方案步骤 %d 的 result 必须为 completed 或 skipped", item.Number))
		}
		if item.Result == "skipped" && IsSafetyCriticalStep(in.PlanSteps[item.Number-1]) {
			failures = append(failures, fmt.Sprintf("安全关键步骤 %d 不得跳过", item.Number))
		}
		if item.Result == "skipped" && strings.TrimSpace(item.DeviationReason) == "" {
			failures = append(failures, fmt.Sprintf("跳过方案步骤 %d 必须填写偏差原因", item.Number))
		}
	}
	for number := range in.PlanSteps {
		if !seenSteps[number+1] {
			failures = append(failures, fmt.Sprintf("缺少方案步骤 %d 的执行结果", number+1))
		}
	}
	seenBatches := map[string]bool{}
	batchPattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$`)
	for i, material := range in.Materials {
		if strings.TrimSpace(material.Name) == "" {
			failures = append(failures, fmt.Sprintf("第 %d 项耗材名称不能为空", i+1))
		}
		if strings.TrimSpace(material.Batch) == "" {
			failures = append(failures, fmt.Sprintf("第 %d 项耗材批次不能为空", i+1))
		} else if !batchPattern.MatchString(strings.TrimSpace(material.Batch)) {
			failures = append(failures, fmt.Sprintf("第 %d 项耗材批次格式无效", i+1))
		}
		if !material.QuantityPresent {
			failures = append(failures, fmt.Sprintf("第 %d 项耗材数量必须为正数或非空说明", i+1))
		}
		key := strings.ToLower(strings.TrimSpace(material.Batch))
		if seenBatches[key] {
			failures = append(failures, fmt.Sprintf("耗材批次 %s 重复登记", material.Batch))
		}
		seenBatches[key] = true
		if material.ExpiresAt.IsZero() {
			failures = append(failures, fmt.Sprintf("耗材批次 %s 缺少有效期", material.Batch))
		} else if material.ExpiresAt.Before(in.ExecutedAt) {
			failures = append(failures, fmt.Sprintf("耗材批次 %s 执行时已经过期", material.Batch))
		}
	}
	if !in.AfterAt.After(in.BeforeAt) {
		failures = append(failures, "校准后读数时间必须晚于校准前读数")
	}
	if in.AfterAt.After(in.ExecutedAt.Add(time.Minute)) {
		failures = append(failures, "校准后读数不能晚于干预执行时间")
	}
	if strings.TrimSpace(in.BeforeReference) == "" || strings.TrimSpace(in.AfterReference) == "" {
		failures = append(failures, "校准前后读数均必须提供校准参考")
	} else if !strings.EqualFold(strings.TrimSpace(in.BeforeReference), strings.TrimSpace(in.AfterReference)) {
		failures = append(failures, "校准前后参考编号不一致")
	}
	if math.Abs(in.AfterTemperature-in.BeforeTemperature) > 10 {
		failures = append(failures, "校准温度漂移超过 10 摄氏度允许值")
	}
	if math.Abs(in.AfterHumidity-in.BeforeHumidity) > 20 {
		failures = append(failures, "校准湿度漂移超过 20 个百分点允许值")
	}
	return failures
}

type ObservationPoint struct {
	CapturedAt                                      time.Time
	SensorStatus, CalibrationReference, QualityNote string
}

type ObservationQuality struct {
	Segment         int
	Eligible        bool
	ExclusionReason string
}

// DetectIsolatedSpikes identifies points that are far from both neighbours.
// The original readings remain immutable; callers decide whether to exclude them.
func DetectIsolatedSpikes(readings []DiscoveryReading) map[string]string {
	result := map[string]string{}
	if len(readings) < 3 {
		return result
	}
	for i := 1; i < len(readings)-1; i++ {
		if readings[i].Quality == "warning" || readings[i].Quality == "low" || readings[i].SensorStatus == "warning" {
			continue
		}
		prev, cur, next := readings[i-1], readings[i], readings[i+1]
		if math.Abs(cur.Temperature-(prev.Temperature+next.Temperature)/2) > 5 || math.Abs(cur.Humidity-(prev.Humidity+next.Humidity)/2) > 15 {
			result[cur.ID] = "孤立尖峰，偏离相邻读数"
		}
	}
	return result
}

type PlanDependencyInput struct {
	Steps             []string
	Dependencies      map[int][]int
	IsolationRequired bool
}

func ValidatePlanDependencies(in PlanDependencyInput) []string {
	var failures []string
	seen := map[int]bool{}
	for i, step := range in.Steps {
		if strings.TrimSpace(step) == "" {
			failures = append(failures, fmt.Sprintf("steps[%d] 不能为空", i))
			continue
		}
		if seen[i+1] {
			failures = append(failures, fmt.Sprintf("步骤编号 %d 重复", i+1))
		}
		seen[i+1] = true
	}
	visiting, visited := map[int]bool{}, map[int]bool{}
	var visit func(int)
	visit = func(n int) {
		if visiting[n] {
			failures = append(failures, fmt.Sprintf("步骤 %d 存在循环依赖", n))
			return
		}
		if visited[n] {
			return
		}
		visiting[n] = true
		for _, dep := range in.Dependencies[n] {
			if dep < 1 || dep > len(in.Steps) {
				failures = append(failures, fmt.Sprintf("步骤 %d 前置步骤 %d 不存在", n, dep))
				continue
			}
			visit(dep)
		}
		delete(visiting, n)
		visited[n] = true
	}
	for n := range in.Dependencies {
		visit(n)
	}
	if in.IsolationRequired {
		for n, deps := range in.Dependencies {
			_ = n
			for _, dep := range deps {
				if dep > n && strings.Contains(in.Steps[dep-1], "隔离") {
					failures = append(failures, fmt.Sprintf("步骤 %d 不得先于隔离步骤执行", n))
				}
			}
		}
	}
	return failures
}

func CheckObservationBatch(existing []ObservationPoint, incoming []ObservationPoint, maximumGap time.Duration) ([]ObservationQuality, []string) {
	var failures []string
	seen := map[int64]bool{}
	last := time.Time{}
	segment := 1
	if len(existing) > 0 {
		ordered := append([]ObservationPoint(nil), existing...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].CapturedAt.Before(ordered[j].CapturedAt) })
		for _, item := range ordered {
			seen[item.CapturedAt.UnixNano()] = true
		}
		last = ordered[len(ordered)-1].CapturedAt
		if ordered[len(ordered)-1].SensorStatus == "warning" {
			segment++
		}
	}
	results := make([]ObservationQuality, len(incoming))
	for i, item := range incoming {
		if seen[item.CapturedAt.UnixNano()] {
			failures = append(failures, fmt.Sprintf("第 %d 条观察读数时间与既有或批次内读数重复", i+1))
		}
		seen[item.CapturedAt.UnixNano()] = true
		if !last.IsZero() && !item.CapturedAt.After(last) {
			failures = append(failures, fmt.Sprintf("第 %d 条观察读数时间倒序", i+1))
		}
		if !last.IsZero() && item.CapturedAt.Sub(last) > maximumGap {
			segment++
		}
		last = item.CapturedAt
		results[i] = ObservationQuality{Segment: segment, Eligible: item.SensorStatus == "ok"}
		if item.SensorStatus == "warning" {
			results[i].ExclusionReason = "传感器 warning 读数不计入稳定窗口"
			if strings.TrimSpace(item.CalibrationReference) == "" && strings.TrimSpace(item.QualityNote) == "" {
				failures = append(failures, fmt.Sprintf("第 %d 条 warning 读数必须提供校准参考或异常说明", i+1))
			}
			segment++
		}
	}
	return results, failures
}
