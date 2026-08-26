package store

func IsTerminalStatus(status Status) bool { return status == StatusSealed }

func IsOpenStatus(status Status) bool { return status != StatusSealed }
