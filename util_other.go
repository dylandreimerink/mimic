//go:build !linux || !windows
// +build !linux,windows

package mimic

import (
	"time"
)

func timeOfBoot() time.Time {
	return time.Now()
}
