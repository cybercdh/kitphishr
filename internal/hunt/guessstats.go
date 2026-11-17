package hunt

import (
	"sort"
	"sync"
)

// GuessStat is the yield of one kind of generated target.
type GuessStat struct {
	Probes int `json:"probes"`
	Found  int `json:"found"`
}

// GuessStats counts, per target kind (see sources.PhishUrls.Kind), how many
// targets were probed and how many kit URLs each surfaced. Kits found inside
// an open directory are credited to "opendir-via-<kind>", the probe that
// revealed the listing. This is the data for deciding which guesses to keep.
type GuessStats struct {
	mu sync.Mutex
	m  map[string]*GuessStat
}

func NewGuessStats() *GuessStats { return &GuessStats{m: make(map[string]*GuessStat)} }

func (g *GuessStats) get(kind string) *GuessStat {
	if kind == "" {
		kind = "other"
	}
	s, ok := g.m[kind]
	if !ok {
		s = &GuessStat{}
		g.m[kind] = s
	}
	return s
}

// Probe records one probed target of kind.
func (g *GuessStats) Probe(kind string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.get(kind).Probes++
	g.mu.Unlock()
}

// Found records one kit URL surfaced by a target of kind.
func (g *GuessStats) Found(kind string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.get(kind).Found++
	g.mu.Unlock()
}

// Snapshot returns a copy safe to serialise.
func (g *GuessStats) Snapshot() map[string]GuessStat {
	out := map[string]GuessStat{}
	if g == nil {
		return out
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.m {
		out[k] = *v
	}
	return out
}

// Kinds returns the kinds in a stable display order (most probes first).
func (g *GuessStats) Kinds() []string {
	snap := g.Snapshot()
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		if snap[keys[a]].Probes != snap[keys[b]].Probes {
			return snap[keys[a]].Probes > snap[keys[b]].Probes
		}
		return keys[a] < keys[b]
	})
	return keys
}
