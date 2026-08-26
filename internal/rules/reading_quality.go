package rules

type ReadingQuality string

const (
	QualityOK      ReadingQuality = "ok"
	QualityWarning ReadingQuality = "warning"
	QualityLow     ReadingQuality = "low"
)

func QualityAcceptable(value string) bool {
	return value == string(QualityOK) || value == string(QualityWarning)
}
