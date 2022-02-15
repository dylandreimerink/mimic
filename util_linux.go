//go:build linux
// +build linux

package mimic

import (
	"time"

	"golang.org/x/sys/unix"
)

func timeOfBoot() time.Time {
	var info unix.Sysinfo_t
	err := unix.Sysinfo(&info)
	if err != nil {
		return time.Now()
	}

	return time.Now().Add(-time.Second * time.Duration(info.Uptime))
}
