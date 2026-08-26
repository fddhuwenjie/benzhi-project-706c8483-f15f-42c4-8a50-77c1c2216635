package rules

type GateResult struct {
	Allowed bool
	Reasons []string
}

func AllowGate() GateResult { return GateResult{Allowed: true} }
