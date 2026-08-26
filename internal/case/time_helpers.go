package cases

import "time"

func IsPast(value, now time.Time) bool { return value.Before(now) }
