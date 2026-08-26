package cases

import "museumenv/internal/store"

func CanAdvance(status store.Status) bool { return status != store.StatusSealed }
