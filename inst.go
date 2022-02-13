package mimic

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

var instructions [256]Instruction

type Instruction func(inst asm.Instruction, process *Process) error

func init() {
	initGen()
	initCustom()
}

// init func for hand crafted instructions which are so different from the others that writing a generator isn't worth
// the time.
func initCustom() {
	instructions[0] = InstNop

	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Neg)] = InstALU32Neg
	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Neg)|asm.OpCode(asm.RegSource)] = InstALU32Neg
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.Neg)] = InstALU64Neg
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.Neg)|asm.OpCode(asm.RegSource)] = InstALU64Neg

	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Mov)] = InstALU32MovIMM
	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Mov)|asm.OpCode(asm.RegSource)] = InstALU32MovReg
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.Mov)] = InstALU64MovIMM
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.Mov)|asm.OpCode(asm.RegSource)] = InstALU64MovReg

	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Mov)] = InstALU32MovIMM
	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Mov)|asm.OpCode(asm.RegSource)] = InstALU32MovReg
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.Mov)] = InstALU64MovIMM
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.Mov)|asm.OpCode(asm.RegSource)] = InstALU64MovReg

	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.ArSh)] = InstALU32ArShIMM
	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.ArSh)|asm.OpCode(asm.RegSource)] = InstALU32ArShReg
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.ArSh)] = InstALU64ArShIMM
	instructions[asm.OpCode(asm.ALU64Class).SetALUOp(asm.ArSh)|asm.OpCode(asm.RegSource)] = InstALU64ArShReg

	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Swap)] = InstALUToLE
	instructions[asm.OpCode(asm.ALUClass).SetALUOp(asm.Swap)|asm.OpCode(asm.RegSource)] = InstALUToBE

	instructions[asm.OpCode(asm.JumpClass).SetJumpOp(asm.Ja)] = InstJump

	instructions[asm.OpCode(asm.Jump32Class).SetJumpOp(asm.JSet)] = InstJump32JSetIMM
	instructions[asm.OpCode(asm.Jump32Class).SetJumpOp(asm.JSet)|asm.OpCode(asm.RegSource)] = InstJump32JSetReg
	instructions[asm.OpCode(asm.JumpClass).SetJumpOp(asm.JSet)] = InstJump64JSetIMM
	instructions[asm.OpCode(asm.JumpClass).SetJumpOp(asm.JSet)|asm.OpCode(asm.RegSource)] = InstJump64JSetReg

	instructions[asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call)] = InstCall
	instructions[asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call)|asm.OpCode(asm.RegSource)] = InstCallHelperIndirect

	instructions[asm.OpCode(asm.JumpClass).SetJumpOp(asm.Exit)] = InstExit

	instructions[asm.OpCode(asm.LdClass).SetMode(asm.ImmMode).SetSize(asm.DWord)] = InstLoad64Imm
	// TODO Load socket buffer
	instructions[asm.OpCode(asm.LdXClass).SetMode(asm.MemMode).SetSize(asm.Byte)] = InstLoadMemory
	instructions[asm.OpCode(asm.LdXClass).SetMode(asm.MemMode).SetSize(asm.Half)] = InstLoadMemory
	instructions[asm.OpCode(asm.LdXClass).SetMode(asm.MemMode).SetSize(asm.Word)] = InstLoadMemory
	instructions[asm.OpCode(asm.LdXClass).SetMode(asm.MemMode).SetSize(asm.DWord)] = InstLoadMemory

	instructions[asm.OpCode(asm.StClass).SetMode(asm.MemMode).SetSize(asm.Byte)] = InstStoreMemoryImm
	instructions[asm.OpCode(asm.StClass).SetMode(asm.MemMode).SetSize(asm.Half)] = InstStoreMemoryImm
	instructions[asm.OpCode(asm.StClass).SetMode(asm.MemMode).SetSize(asm.Word)] = InstStoreMemoryImm
	instructions[asm.OpCode(asm.StClass).SetMode(asm.MemMode).SetSize(asm.DWord)] = InstStoreMemoryImm

	instructions[asm.OpCode(asm.StXClass).SetMode(asm.MemMode).SetSize(asm.Byte)] = InstStoreMemoryReg
	instructions[asm.OpCode(asm.StXClass).SetMode(asm.MemMode).SetSize(asm.Half)] = InstStoreMemoryReg
	instructions[asm.OpCode(asm.StXClass).SetMode(asm.MemMode).SetSize(asm.Word)] = InstStoreMemoryReg
	instructions[asm.OpCode(asm.StXClass).SetMode(asm.MemMode).SetSize(asm.DWord)] = InstStoreMemoryReg

	// TODO atomics
}

// InstNop doesn't officially exist, and doesn't do anything. It exists to be added after LDImm64 instructions,
// jump offsets count them as 2 instructions but in the instructions slice it is only one instruction.
func InstNop(i asm.Instruction, process *Process) error {
	return nil
}

func InstALU32Neg(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	return process.Registers.Set(i.Dst, uint64(-int32(dst)))
}

func InstALU64Neg(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	return process.Registers.Set(i.Dst, uint64(-int64(dst)))
}

func InstALU32MovIMM(i asm.Instruction, process *Process) error {
	// TODO is this correct, or should we preserve the upper 32bits?
	return process.Registers.Set(i.Dst, uint64(uint32(i.Constant)))
}

func InstALU32MovReg(i asm.Instruction, process *Process) error {
	// TODO is this correct, or should we preserve the upper 32bits?
	src := process.Registers.Get(i.Src)
	return process.Registers.Set(i.Dst, uint64(uint32(src)))
}

func InstALU64MovIMM(i asm.Instruction, process *Process) error {
	return process.Registers.Set(i.Dst, uint64(i.Constant))
}

func InstALU64MovReg(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	return process.Registers.Set(i.Dst, src)
}

func InstALU32ArShIMM(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	return process.Registers.Set(i.Dst, uint64(int32(dst)>>i.Constant))
}

func InstALU32ArShReg(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	dst := process.Registers.Get(i.Dst)
	return process.Registers.Set(i.Dst, uint64(int32(dst)>>src))
}

func InstALU64ArShIMM(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	return process.Registers.Set(i.Dst, uint64(int64(dst)>>i.Constant))
}

func InstALU64ArShReg(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	dst := process.Registers.Get(i.Dst)
	return process.Registers.Set(i.Dst, uint64(int64(dst)>>src))
}

func InstALUToLE(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	switch i.Constant {
	case 16:
		dst = uint64(binary.LittleEndian.Uint16([]byte{
			byte(dst >> 8),
			byte(dst >> 0),
		}))
	case 32:
		dst = uint64(binary.LittleEndian.Uint32([]byte{
			byte(dst >> 24),
			byte(dst >> 16),
			byte(dst >> 8),
			byte(dst >> 0),
		}))
	case 64:
		dst = uint64(binary.LittleEndian.Uint32([]byte{
			byte(dst >> 56),
			byte(dst >> 48),
			byte(dst >> 40),
			byte(dst >> 32),
			byte(dst >> 24),
			byte(dst >> 16),
			byte(dst >> 8),
			byte(dst >> 0),
		}))
	}

	return process.Registers.Set(i.Dst, dst)
}

func InstALUToBE(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	switch i.Constant {
	case 16:
		dst = uint64(binary.BigEndian.Uint16([]byte{
			byte(dst >> 8),
			byte(dst >> 0),
		}))
	case 32:
		dst = uint64(binary.BigEndian.Uint32([]byte{
			byte(dst >> 24),
			byte(dst >> 16),
			byte(dst >> 8),
			byte(dst >> 0),
		}))
	case 64:
		dst = uint64(binary.BigEndian.Uint32([]byte{
			byte(dst >> 56),
			byte(dst >> 48),
			byte(dst >> 40),
			byte(dst >> 32),
			byte(dst >> 24),
			byte(dst >> 16),
			byte(dst >> 8),
			byte(dst >> 0),
		}))
	}

	return process.Registers.Set(i.Dst, dst)
}

func InstJump(i asm.Instruction, process *Process) error {
	process.Registers.PC += int(i.Offset)
	return nil
}

func InstJump32JSetIMM(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	if uint32(dst)&uint32(i.Constant) == 0 {
		process.Registers.PC += int(i.Offset)
	}

	return nil
}

func InstJump64JSetIMM(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	if dst&uint64(i.Constant) == 0 {
		process.Registers.PC += int(i.Offset)
	}

	return nil
}

func InstJump32JSetReg(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	dst := process.Registers.Get(i.Dst)
	if uint32(dst)&uint32(src) == 0 {
		process.Registers.PC += int(i.Offset)
	}

	return nil
}

func InstJump64JSetReg(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	dst := process.Registers.Get(i.Dst)
	if dst&src == 0 {
		process.Registers.PC += int(i.Offset)
	}

	return nil
}

func InstCall(i asm.Instruction, process *Process) error {
	if i.Src == asm.PseudoCall {
		// BPF-to-BPF call

		// value copy, all fields are uint64'es
		r := process.Registers
		// Save current registers
		process.calleeSavedRegister = append(process.calleeSavedRegister, r)
		// Add offset to PC, subtract one since we will increment PC after this instruction, the result is that we
		// end exactly at the desired instruction.
		process.Registers.PC += int(i.Constant) - 1
		// Increment the Stack Frame pointer by the size of a single frame
		process.Registers.R10 += uint64(process.VM.settings.StackFrameSize)

		return nil
	}

	// Helper call
	if process.VM.settings.Emulator == nil {
		return fmt.Errorf("vm has no emulator, can't call helper functions")
	}

	return process.VM.settings.Emulator.CallHelperFunction(int32(i.Constant), process)
}

// InstCallHelperIndirect is illegal in the linux kernel, but we have it here to support non-kernel eBPF implementation.
// This instruction is generated by clang when optimizations are disabled.
func InstCallHelperIndirect(i asm.Instruction, process *Process) error {
	// Helper call, id of the helper resides in the register marked by i.Constant
	panic("not yet implemented")
}

var errExit = errors.New("function/program exit")

func InstExit(i asm.Instruction, process *Process) error {
	// If there are callee saves registers, we are returning from a BPF-to-BPF function.
	if len(process.calleeSavedRegister) > 0 {
		// Restore the only the callee saved registers and program counter
		saved := process.calleeSavedRegister[len(process.calleeSavedRegister)-1]
		process.Registers.PC = saved.PC
		process.Registers.R6 = saved.R6
		process.Registers.R7 = saved.R7
		process.Registers.R8 = saved.R8
		process.Registers.R9 = saved.R9
		// Shrink the slice (deleting the last element)
		process.calleeSavedRegister = process.calleeSavedRegister[:len(process.calleeSavedRegister)-1]
		// Move Stack Frame pointer up by the size of one stack frame
		process.Registers.R10 -= uint64(process.VM.settings.StackFrameSize)

		return nil
	}

	return errExit
}

func InstLoadMemory(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	addr := uint32(src + uint64(i.Offset))

	entry, off, found := process.VM.MemoryController.GetEntry(addr)
	if !found {
		return fmt.Errorf("memory controller can't resolve address 0x%x", addr)
	}

	vmMem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("eBPF VM not allowed to access memory object at 0x%x", addr)
	}

	val, err := vmMem.Load(off, i.OpCode.Size())
	if err != nil {
		return fmt.Errorf("load from vm memory: %w", err)
	}

	return process.Registers.Set(i.Dst, val)
}

func InstStoreMemoryImm(i asm.Instruction, process *Process) error {
	dst := process.Registers.Get(i.Dst)
	addr := uint32(dst + uint64(i.Offset))

	entry, off, found := process.VM.MemoryController.GetEntry(addr)
	if !found {
		return fmt.Errorf("memory controller can't resolve address 0x%x", addr)
	}

	vmMem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("eBPF VM not allowed to access memory object at 0x%x", addr)
	}

	err := vmMem.Store(off, uint64(i.Constant), i.OpCode.Size())
	if err != nil {
		return fmt.Errorf("store to vm memory: %w", err)
	}

	return nil
}

func InstStoreMemoryReg(i asm.Instruction, process *Process) error {
	src := process.Registers.Get(i.Src)
	dst := process.Registers.Get(i.Dst)
	addr := uint32(dst + uint64(i.Offset))

	entry, off, found := process.VM.MemoryController.GetEntry(addr)
	if !found {
		return fmt.Errorf("memory controller can't resolve address 0x%x", addr)
	}

	vmMem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("eBPF VM not allowed to access memory object at 0x%x", addr)
	}

	err := vmMem.Store(off, src, i.OpCode.Size())
	if err != nil {
		return fmt.Errorf("store to vm memory: %w", err)
	}

	return nil
}

func InstLoad64Imm(i asm.Instruction, process *Process) error {
	return process.Registers.Set(i.Dst, uint64(i.Constant))
}
