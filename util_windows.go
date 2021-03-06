//go:build windows
// +build windows

package mimic

import (
	"time"

	"golang.org/x/sys/windows"
)

func timeOfBoot() time.Time {
	return time.Now().Add(time.Duration(-1) * windows.DurationSinceBoot())
}
