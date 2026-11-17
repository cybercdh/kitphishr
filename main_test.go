package main

import (
	"strings"
	"testing"
	"time"
)

func TestFormatETA(t *testing.T) {
	cases := map[time.Duration]string{
		42 * time.Second:                "42s",
		17*time.Minute + 20*time.Second: "17m",
		2*time.Hour + 5*time.Minute:     "2h05m",
	}
	for d, want := range cases {
		if got := formatETA(d); got != want {
			t.Errorf("formatETA(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestProgressLine(t *testing.T) {
	// 1000 of 4000 done at a smoothed 50/s -> 3000 left -> 60s -> "1m".
	got := progressLine(90*time.Second, 1000, 4000, 48, 50, 2, 1, 7)
	for _, want := range []string{"[1m30s]", "1000/4000 (25.0%)", "48/s", "ETA 1m", "found=2 saved=1 dead-hosts=7"} {
		if !strings.Contains(got, want) {
			t.Errorf("progress line %q missing %q", got, want)
		}
	}
	if got := progressLine(5*time.Second, 0, 0, 0, 0, 0, 0, 0); !strings.Contains(got, "preparing targets") {
		t.Errorf("before targets are known: %q", got)
	}
	// Open-dir follow-ups can push done past the plan; never show >100%.
	if got := progressLine(time.Minute, 5000, 4000, 10, 10, 0, 0, 0); !strings.Contains(got, "4000/4000 (100.0%)") {
		t.Errorf("overshoot not clamped: %q", got)
	}
}
