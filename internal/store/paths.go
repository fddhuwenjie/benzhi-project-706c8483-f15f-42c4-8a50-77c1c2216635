package store

import "path/filepath"

func SnapshotPath(directory string) string { return filepath.Join(directory, "snapshot.json") }
func AuditPath(directory string) string    { return filepath.Join(directory, "audit.jsonl") }
