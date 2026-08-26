package cases

type Actor struct {
	ID   string
	Role string
}

func (a Actor) Present() bool { return a.ID != "" }
