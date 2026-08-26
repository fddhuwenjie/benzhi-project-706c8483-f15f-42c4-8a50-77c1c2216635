package rules

import (
	"strings"
	"testing"
	"time"
)

func TestAssessRiskCritical(t *testing.T) {
	assessment, err := AssessRisk(RiskInput{Temperature: 30, Humidity: 75, TargetTemperature: Range{Min: 18, Max: 22}, TargetHumidity: Range{Min: 45, Max: 55}, Duration: 26 * time.Hour, Sensitivity: SensitivityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Level != RiskCritical {
		t.Fatalf("risk = %s, want critical", assessment.Level)
	}
	if assessment.ResponseWithin != 30*time.Minute {
		t.Fatalf("deadline duration = %s", assessment.ResponseWithin)
	}
	if len(assessment.Reasons) < 3 {
		t.Fatalf("reasons = %v", assessment.Reasons)
	}
}

func TestValidatePlanRequiresIsolationForHighRisk(t *testing.T) {
	failures := ValidatePlan(PlanInput{Steps: []string{"更换调湿材料"}, TemperatureTarget: Range{Min: 18, Max: 22}, HumidityTarget: Range{Min: 45, Max: 55}, RiskLevel: RiskHigh})
	if len(failures) != 1 {
		t.Fatalf("failures = %v", failures)
	}
}

func TestEvaluateRecovery(t *testing.T) {
	start := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	readings := []RecoveryReading{
		{CapturedAt: start, Temperature: 20, Humidity: 50, SensorOK: true},
		{CapturedAt: start.Add(30 * time.Minute), Temperature: 20.2, Humidity: 50.5, SensorOK: true},
		{CapturedAt: start.Add(60 * time.Minute), Temperature: 20.1, Humidity: 51, SensorOK: true},
	}
	result := EvaluateRecovery(readings, RecoveryPolicy{TemperatureTarget: Range{Min: 18, Max: 22}, HumidityTarget: Range{Min: 45, Max: 55}, MinimumStableDuration: time.Hour, MinimumReadings: 3})
	if !result.Qualified {
		t.Fatalf("unexpected failures: %v", result.Failures)
	}
	readings[1].Humidity = 61
	result = EvaluateRecovery(readings, RecoveryPolicy{TemperatureTarget: Range{Min: 18, Max: 22}, HumidityTarget: Range{Min: 45, Max: 55}, MinimumStableDuration: time.Hour, MinimumReadings: 3})
	if result.Qualified || len(result.Failures) == 0 {
		t.Fatal("out-of-range observation was accepted")
	}
}

func TestCheckReopenGateExplainsEveryFailure(t *testing.T) {
	failures := CheckReopenGate(ReopenGate{})
	if len(failures) != 4 {
		t.Fatalf("failures = %v", failures)
	}
}

func TestCheckExecutionReturnsAllNonconformities(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	failures := CheckExecution(ExecutionCheck{PlanSteps: []string{"设置隔离", "更换材料"}, Steps: []ExecutionStep{{Number: 2, Result: "completed"}}, Materials: []ExecutionMaterial{{Name: "调湿材料", Batch: "expired", QuantityPresent: true, ExpiresAt: now.Add(-time.Hour)}}, ExecutedAt: now, BeforeAt: now.Add(-2 * time.Hour), AfterAt: now.Add(-time.Hour), BeforeReference: "ref", AfterReference: "ref"})
	if len(failures) < 2 {
		t.Fatalf("failures = %v", failures)
	}
}

func TestObservationWarningRequiresTraceAndStartsNewSegment(t *testing.T) {
	start := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	quality, failures := CheckObservationBatch(nil, []ObservationPoint{{CapturedAt: start, SensorStatus: "warning"}, {CapturedAt: start.Add(10 * time.Minute), SensorStatus: "ok"}}, 30*time.Minute)
	if len(failures) != 1 || quality[0].Eligible || quality[1].Segment == quality[0].Segment {
		t.Fatalf("quality=%+v failures=%v", quality, failures)
	}
}

func TestDiscoveryBatchUsesPeakRiskAndShortestDeadline(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	assessment, err := AssessDiscoveryBatch([]DiscoveryReading{
		{ID: "read-1", CapturedAt: now.Add(-20 * time.Minute), Temperature: 21, Humidity: 52},
		{ID: "read-peak", CapturedAt: now.Add(-10 * time.Minute), Temperature: 31, Humidity: 80},
		{ID: "read-3", CapturedAt: now, Temperature: 22, Humidity: 54},
	}, Range{Min: 18, Max: 22}, Range{Min: 45, Max: 55}, now.Add(-6*time.Hour), now, SensitivityHigh)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.PeakReadingID != "read-peak" || assessment.Level != RiskCritical || assessment.ResponseWithin != 30*time.Minute {
		t.Fatalf("assessment = %+v", assessment)
	}
}

func TestRecoveryProgressRestartsAfterThresholdInterruption(t *testing.T) {
	start := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	policy := RecoveryPolicy{TemperatureTarget: Range{Min: 18, Max: 22}, HumidityTarget: Range{Min: 45, Max: 55}, MinimumStableDuration: time.Hour, MinimumReadings: 3, MaximumGap: 30 * time.Minute}
	progress := CalculateRecoveryProgress([]RecoveryReading{
		{CapturedAt: start, Temperature: 20, Humidity: 50, SensorOK: true},
		{CapturedAt: start.Add(20 * time.Minute), Temperature: 20, Humidity: 70, SensorOK: true},
		{CapturedAt: start.Add(30 * time.Minute), Temperature: 20, Humidity: 50, SensorOK: true},
		{CapturedAt: start.Add(50 * time.Minute), Temperature: 20, Humidity: 50, SensorOK: true},
	}, policy, "policy-1")
	if progress.StableMinutes != 20 || progress.ValidReadings != 2 || progress.RemainingMinutes != 40 || progress.LatestInterruption == "" {
		t.Fatalf("progress = %+v", progress)
	}
}

func TestSafetyEnvelopeReportsActualAndAllowedValue(t *testing.T) {
	failures := CheckEnvelopeExecution(SafetyEnvelopeInput{MaxTemperatureChangePerHour: 1, MaxHumidityChangePerHour: 3, MaxExposureMinutes: 60, StopTemperature: Range{Min: 10, Max: 30}, StopHumidity: Range{Min: 20, Max: 80}}, EnvelopeActual{DurationMinutes: 30, TemperatureBefore: 20, TemperatureAfter: 21, HumidityBefore: 50, HumidityAfter: 55})
	if len(failures) != 2 || !strings.Contains(failures[0], "允许值") || !strings.Contains(failures[0], "实际值") {
		t.Fatalf("failures = %v", failures)
	}
}
