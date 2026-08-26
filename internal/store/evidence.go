package store

type EvidenceDigest struct {
	Algorithm string
	Value     string
}

func (d EvidenceDigest) Valid() bool { return d.Algorithm != "" && d.Value != "" }
