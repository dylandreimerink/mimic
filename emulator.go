package mimic

import "github.com/cilium/ebpf"

// Emulator describes a struct which implements eBPF features which are specific to a certain environment.
type Emulator interface {
	// SetVM is called when an emulator is linked to a VM, this allows the emulator to save a reference
	// so it can access information about the VM like the memory controller.
	SetVM(vm *VM)
	// CallHelperFunction is called when a process executes a call to a helper function. The emulator must make sure
	// that this call is thread-safe in go-land, meaning that we should not allow raceconditions in the vm/emulator.
	// However, eBPF programs are themselves responsible for race-conditions in VM memory.
	//
	// If this function returns an error, a un-graceful error is assumed which will abort further execution of the
	// program and forwards the error to the process callee. Helper functions can also define graceful errors, which
	// can be returned to the calling program by setting the R0 register for example.
	CallHelperFunction(helperNr int32, p *Process) error
	// RewriteProgram is called when a program is loaded into the VM. At this point the emulator may rewrite parts
	// of the program with emulator specific references, map addresses for example. If an error is returned the program
	// loading is halted.
	RewriteProgram(program *ebpf.ProgramSpec) error
}
