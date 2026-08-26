package rules

type SensitivityLevel string

const (
	SensitivityLevelLow     SensitivityLevel = "low"
	SensitivityLevelMedium  SensitivityLevel = "medium"
	SensitivityLevelHigh    SensitivityLevel = "high"
	SensitivityLevelUnknown SensitivityLevel = "unknown"
)

func NormalizeSensitivity(value string) SensitivityLevel {
	switch Sensitivity(value) {
	case SensitivityLow:
		return SensitivityLevelLow
	case SensitivityMedium:
		return SensitivityLevelMedium
	case SensitivityHigh:
		return SensitivityLevelHigh
	default:
		return SensitivityLevelUnknown
	}
}
