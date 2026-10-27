//go:build !race

package ratify_test

// v2RaceDetector reports that the race detector instruments this test
// binary. Long sequential sweeps run in full only without it.
const v2RaceDetector = false
