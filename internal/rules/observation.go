package rules

import "time"

type ObservationWindow struct {
	StartedAt time.Time
	Duration  time.Duration
}

func (w ObservationWindow) EndsAt() time.Time { return w.StartedAt.Add(w.Duration) }
