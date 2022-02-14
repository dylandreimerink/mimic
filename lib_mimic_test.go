package mimic_test

import "github.com/dylandreimerink/mimic"

// This files contains functions to be used in units tests, handy since setting up the environment can be very
// repetitive

func testEnv() (*mimic.VM, *mimic.LinuxEmulator) {
	emu := mimic.NewLinuxEmulator()
	vm := mimic.NewVM(mimic.VMOptEmulator(emu))

	return vm, emu
}
