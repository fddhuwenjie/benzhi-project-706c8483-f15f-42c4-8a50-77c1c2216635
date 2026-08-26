package store

type Transaction struct {
	Mutation Mutation
	Before   *EnvironmentIncident
	After    *EnvironmentIncident
}

func (t Transaction) Changed() bool { return t.Before != t.After }
