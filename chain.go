package goblkid

type Chain []Prober

func (chain Chain) Probe(info *ProbeInfo) bool {
	for _, prober := range chain {
		if prober.Probe(info) {
			info.ProbeName = prober.Name
			return true
		}
	}
	return false
}
