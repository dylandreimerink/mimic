package mimic

// This files contains functions to be used in units tests, handy since setting up the environment can be very
// repetitive

func testEnv() (*VM, *LinuxEmulator) {
	emu := NewLinuxEmulator()
	vm := NewVM(VMOptEmulator(emu))

	return vm, emu
}
