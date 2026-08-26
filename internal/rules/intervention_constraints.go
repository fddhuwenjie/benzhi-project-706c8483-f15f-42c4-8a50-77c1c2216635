package rules

type InterventionConstraint struct {
	IsolationRequired bool
	MaximumStepCount  int
	RequiresReview    bool
}

func DefaultInterventionConstraint() InterventionConstraint {
	return InterventionConstraint{MaximumStepCount: 20, RequiresReview: true}
}
