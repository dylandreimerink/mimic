//go:build darwin
// +build darwin

package mimic

import (
	"time"

	"golang.org/x/sys/unix"
)

func timeOfBoot() time.Time {
	var spec unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &spec)
	if err != nil {
		return time.Now()
	}

	return time.Now().Add(-time.Second*time.Duration(spec.Sec) + time.Duration(-1)*time.Duration(spec.Nsec))
}
