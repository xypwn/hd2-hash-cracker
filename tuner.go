package main

import (
	"github.com/xypwn/hd2-hash-cracker/util"
)

const secondNs = 1e9

type tunerSample struct {
	RunDurationNs int
	NewTries      int
}

// Stats of a single test runcomposed
// of multiple samples
type tunerSampleRun struct {
	// Variables
	Workers int
	Tries   int

	// Stats
	Collected        bool
	NsUntilCollected int
	AvgNsPerTry      float64
	Reports          util.RingBuf[tunerSample]
}

type Tuner struct {
	remainingWarmupNs int

	// Relative to current workers, e.g. 0.5 means
	// increase multiply by 1.5.
	workerIncStep float64

	baseline   tunerSampleRun
	experiment tunerSampleRun

	done bool
}

func NewTuner(workers, tries int) *Tuner {
	return &Tuner{
		remainingWarmupNs: 2 * secondNs,
		baseline: tunerSampleRun{
			Workers:          workers,
			Tries:            tries,
			NsUntilCollected: 2 * secondNs,
		},
		workerIncStep: 1,
	}
}

// Tuner that does nothing. Useful for debugging.
func NewDummyTuner() *Tuner {
	return &Tuner{
		done: true,
	}
}

// Other return values are only valid if changed is true.
func (t *Tuner) Step(computeRunDurationNs int, totalHashesTried int) (newNumWorkers, newNumTries int, done, changed bool) {
	if t.remainingWarmupNs > 0 {
		t.remainingWarmupNs -= computeRunDurationNs
		return
	}

	if t.done {
		return
	}

	collectStats := func(s *tunerSampleRun) (justFinished bool) {
		if s.Collected {
			return
		}
		s.Reports.Write(tunerSample{computeRunDurationNs, totalHashesTried})
		s.NsUntilCollected -= computeRunDurationNs
		if s.NsUntilCollected <= 0 {
			// We have enough data now
			{ // average ns per per try
				var acc float64
				for r := range s.Reports.PeekAllIter() {
					acc += float64(r.RunDurationNs) / float64(r.NewTries)
				}
				s.AvgNsPerTry = acc / float64(s.Reports.Len())
			}
			s.Collected = true
			justFinished = true
		}
		return
	}

	calcTries := func(workers int, avgNsPerTry float64) int {
		avgSPerTry := avgNsPerTry / secondNs
		targetComputeRunDuration := 0.2 // in seconds
		return int(targetComputeRunDuration /
			(float64(workers) * avgSPerTry)) // time it takes for every worker to do 1 try
	}

	startNewExperiment := false

	if !t.baseline.Collected {
		// Collect initial baseline
		if collectStats(&t.baseline) {
			// Baseline data collected => start first experiment
			startNewExperiment = true
		}
	} else {
		// Collect experiment data
		if collectStats(&t.experiment) {
			// Experiment data collected => determine whether to use new variables
			gain := t.baseline.AvgNsPerTry / t.experiment.AvgNsPerTry
			if gain >= 1.05 {
				// Accept new variables
				t.baseline = t.experiment
			} else {
				if t.workerIncStep <= 0.05 {
					// Finish by accepting the baseline
					newNumWorkers = t.baseline.Workers
					newNumTries = calcTries(t.baseline.Workers, t.baseline.AvgNsPerTry)
					newNumTries *= 2 // increase stability; since we're no longer probing, we can afford the longer kernel runtime
					done = true
					changed = true
					return
				}

				// Reject new variables -> half worker increase
				t.workerIncStep /= 2
			}
			// Start new experiment
			startNewExperiment = true
		}
	}

	if startNewExperiment {
		expWorkers := int(float64(t.baseline.Workers) * (1 + t.workerIncStep))
		t.experiment = tunerSampleRun{
			Workers:          expWorkers,
			Tries:            calcTries(expWorkers, t.baseline.AvgNsPerTry),
			NsUntilCollected: 2 * secondNs,
		}
		newNumWorkers = t.experiment.Workers
		newNumTries = t.experiment.Tries
		changed = true
	}

	return
}
