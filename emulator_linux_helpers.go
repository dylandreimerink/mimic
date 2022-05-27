package mimic

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// HelperFunction is a function defined in Go which can be invoked by the eBPF VM via the Call instruction.
// The emulator has a lookup map which maps a particular number to a helper function. Helper functions are used as a
// interface between the sandboxed eBPF VM and the Emulator/Host/Outside world. Helper functions are responsible for
// security checks and should implement policies or other forms of limitations to guarantee that eBPF code can't be used
// for malicious purposes.
//
// Helper functions are called with eBPF calling convention, meaning R1-R5 are arguments, and R0 is the return value.
// Errors returned by the helper are considered fatal for the process, are passed to the process and will result in it
// aborting. Recoverable errors/graceful errors should be returned to the VM via the R0 register and a helper func
// specific contract.
type HelperFunction func(p *Process) error

var (
	// A mapping of emulated helper functions, functions in this list MAY be replayed with the emulated version as
	// fallback, or replaying may not be possible at all.
	emulatedLinuxHelpers = []HelperFunction{
		0:                                nil, // 0 is not a valid helper function
		asm.FnMapLookupElem:              linuxHelperMapLookupElem,
		asm.FnMapUpdateElem:              linuxHelperMapUpdateElem,
		asm.FnMapDeleteElem:              linuxHelperMapDeleteElem,
		asm.FnProbeRead:                  linuxHelperCantEmulate,
		asm.FnKtimeGetNs:                 linuxHelperGetKTimeNs,
		asm.FnGetPrandomU32:              linuxHelperGetPRandomU32,
		asm.FnGetSmpProcessorId:          linuxHelperGetSmpProcessorID,
		asm.FnSkbStoreBytes:              linuxHelperSKBStoreBytes,
		asm.FnL3CsumReplace:              nil, // TODO
		asm.FnL4CsumReplace:              nil, // TODO
		asm.FnTailCall:                   linuxHelperTailcall,
		asm.FnCloneRedirect:              nil, // TODO
		asm.FnGetCurrentPidTgid:          linuxHelperCantEmulate,
		asm.FnGetCurrentUidGid:           linuxHelperCantEmulate,
		asm.FnGetCurrentComm:             linuxHelperCantEmulate,
		asm.FnGetCgroupClassid:           linuxHelperCantEmulate,
		asm.FnSkbVlanPush:                nil, // TODO
		asm.FnSkbVlanPop:                 nil, // TODO
		asm.FnSkbGetTunnelKey:            nil, // TODO
		asm.FnSkbSetTunnelKey:            nil, // TODO
		asm.FnPerfEventRead:              linuxHelperCantEmulate,
		asm.FnRedirect:                   nil, // TODO
		asm.FnGetRouteRealm:              linuxHelperCantEmulate,
		asm.FnPerfEventOutput:            linuxHelperEventOutput,
		asm.FnSkbLoadBytes:               nil, // TODO
		asm.FnGetStackid:                 linuxHelperCantEmulate,
		asm.FnCsumDiff:                   nil, // TODO
		asm.FnSkbGetTunnelOpt:            nil, // TODO
		asm.FnSkbSetTunnelOpt:            nil, // TODO
		asm.FnSkbChangeProto:             nil, // TODO
		asm.FnSkbChangeType:              nil, // TODO
		asm.FnSkbUnderCgroup:             nil, // TODO
		asm.FnGetHashRecalc:              nil, // TODO
		asm.FnGetCurrentTask:             linuxHelperCantEmulate,
		asm.FnProbeWriteUser:             linuxHelperCantEmulate,
		asm.FnCurrentTaskUnderCgroup:     nil, // TODO
		asm.FnSkbChangeTail:              nil, // TODO
		asm.FnSkbPullData:                nil, // TODO
		asm.FnCsumUpdate:                 nil, // TODO
		asm.FnSetHashInvalid:             nil, // TODO
		asm.FnGetNumaNodeId:              linuxHelperCantEmulate,
		asm.FnSkbChangeHead:              nil, // TODO
		asm.FnXdpAdjustHead:              nil, // TODO
		asm.FnProbeReadStr:               linuxHelperCantEmulate,
		asm.FnGetSocketCookie:            linuxHelperCantEmulate,
		asm.FnGetSocketUid:               linuxHelperCantEmulate,
		asm.FnSetHash:                    nil, // TODO
		asm.FnSetsockopt:                 nil, // TODO
		asm.FnSkbAdjustRoom:              nil, // TODO
		asm.FnRedirectMap:                nil, // TODO
		asm.FnSkRedirectMap:              nil, // TODO
		asm.FnSockMapUpdate:              nil, // TODO
		asm.FnXdpAdjustMeta:              nil, // TODO
		asm.FnPerfEventReadValue:         linuxHelperCantEmulate,
		asm.FnPerfProgReadValue:          linuxHelperCantEmulate,
		asm.FnGetsockopt:                 nil, // TODO
		asm.FnOverrideReturn:             nil, // TODO
		asm.FnSockOpsCbFlagsSet:          nil, // TODO
		asm.FnMsgRedirectMap:             nil, // TODO
		asm.FnMsgApplyBytes:              nil, // TODO
		asm.FnMsgCorkBytes:               nil, // TODO
		asm.FnMsgPullData:                nil, // TODO
		asm.FnBind:                       nil, // TODO
		asm.FnXdpAdjustTail:              linuxHelperXDPAdjustTail,
		asm.FnSkbGetXfrmState:            nil, // TODO
		asm.FnGetStack:                   linuxHelperCantEmulate,
		asm.FnSkbLoadBytesRelative:       nil, // TODO
		asm.FnFibLookup:                  linuxHelperCantEmulate,
		asm.FnSockHashUpdate:             nil, // TODO
		asm.FnMsgRedirectHash:            nil, // TODO
		asm.FnSkRedirectHash:             nil, // TODO
		asm.FnLwtPushEncap:               nil, // TODO
		asm.FnLwtSeg6StoreBytes:          nil, // TODO
		asm.FnLwtSeg6AdjustSrh:           nil, // TODO
		asm.FnLwtSeg6Action:              nil, // TODO
		asm.FnRcRepeat:                   nil, // TODO
		asm.FnRcKeydown:                  nil, // TODO
		asm.FnSkbCgroupId:                nil, // TODO
		asm.FnGetCurrentCgroupId:         linuxHelperCantEmulate,
		asm.FnGetLocalStorage:            nil, // TODO
		asm.FnSkSelectReuseport:          nil, // TODO
		asm.FnSkbAncestorCgroupId:        nil, // TODO
		asm.FnSkLookupTcp:                nil, // TODO
		asm.FnSkLookupUdp:                nil, // TODO
		asm.FnSkRelease:                  nil, // TODO
		asm.FnMapPushElem:                linuxHelperMapPushElem,
		asm.FnMapPopElem:                 linuxHelperMapPopElem,
		asm.FnMapPeekElem:                linuxHelperMapPeekElem,
		asm.FnMsgPushData:                nil, // TODO
		asm.FnMsgPopData:                 nil, // TODO
		asm.FnRcPointerRel:               nil, // TODO
		asm.FnSpinLock:                   nil, // TODO
		asm.FnSpinUnlock:                 nil, // TODO
		asm.FnSkFullsock:                 nil, // TODO
		asm.FnTcpSock:                    nil, // TODO
		asm.FnSkbEcnSetCe:                nil, // TODO
		asm.FnGetListenerSock:            nil, // TODO
		asm.FnSkcLookupTcp:               nil, // TODO
		asm.FnTcpCheckSyncookie:          nil, // TODO
		asm.FnSysctlGetName:              nil, // TODO
		asm.FnSysctlGetCurrentValue:      nil, // TODO
		asm.FnSysctlGetNewValue:          nil, // TODO
		asm.FnSysctlSetNewValue:          nil, // TODO
		asm.FnStrtol:                     nil, // TODO
		asm.FnStrtoul:                    nil, // TODO
		asm.FnSkStorageGet:               nil, // TODO
		asm.FnSkStorageDelete:            nil, // TODO
		asm.FnSendSignal:                 nil, // TODO
		asm.FnTcpGenSyncookie:            nil, // TODO
		asm.FnSkbOutput:                  nil, // TODO
		asm.FnProbeReadUser:              linuxHelperCantEmulate,
		asm.FnProbeReadKernel:            linuxHelperCantEmulate,
		asm.FnProbeReadUserStr:           linuxHelperCantEmulate,
		asm.FnProbeReadKernelStr:         linuxHelperCantEmulate,
		asm.FnTcpSendAck:                 nil, // TODO
		asm.FnSendSignalThread:           nil, // TODO
		asm.FnJiffies64:                  nil, // TODO
		asm.FnReadBranchRecords:          linuxHelperCantEmulate,
		asm.FnGetNsCurrentPidTgid:        linuxHelperCantEmulate,
		asm.FnXdpOutput:                  nil, // TODO
		asm.FnGetNetnsCookie:             linuxHelperCantEmulate,
		asm.FnGetCurrentAncestorCgroupId: linuxHelperCantEmulate,
		asm.FnSkAssign:                   nil, // TODO
		asm.FnKtimeGetBootNs:             linuxHelperGetKTimeNs,
		asm.FnSeqPrintf:                  nil, // TODO
		asm.FnSeqWrite:                   nil, // TODO
		asm.FnSkCgroupId:                 linuxHelperCantEmulate,
		asm.FnSkAncestorCgroupId:         linuxHelperCantEmulate,
		asm.FnRingbufOutput:              nil, // TODO
		asm.FnRingbufReserve:             nil, // TODO
		asm.FnRingbufSubmit:              nil, // TODO
		asm.FnRingbufDiscard:             nil, // TODO
		asm.FnRingbufQuery:               nil, // TODO
		asm.FnCsumLevel:                  nil, // TODO
		asm.FnSkcToTcp6Sock:              nil, // TODO
		asm.FnSkcToTcpSock:               nil, // TODO
		asm.FnSkcToTcpTimewaitSock:       nil, // TODO
		asm.FnSkcToTcpRequestSock:        nil, // TODO
		asm.FnSkcToUdp6Sock:              nil, // TODO
		asm.FnGetTaskStack:               linuxHelperCantEmulate,
		asm.FnLoadHdrOpt:                 nil, // TODO
		asm.FnStoreHdrOpt:                nil, // TODO
		asm.FnReserveHdrOpt:              nil, // TODO
		asm.FnInodeStorageGet:            nil, // TODO
		asm.FnInodeStorageDelete:         nil, // TODO
		asm.FnDPath:                      nil, // TODO
		asm.FnCopyFromUser:               linuxHelperCantEmulate,
		asm.FnSnprintfBtf:                nil, // TODO
		asm.FnSeqPrintfBtf:               nil, // TODO
		asm.FnSkbCgroupClassid:           linuxHelperCantEmulate,
		asm.FnRedirectNeigh:              nil, // TODO
		asm.FnPerCpuPtr:                  nil, // TODO
		asm.FnThisCpuPtr:                 nil, // TODO
		asm.FnRedirectPeer:               nil, // TODO
		asm.FnTaskStorageGet:             nil, // TODO
		asm.FnTaskStorageDelete:          nil, // TODO
		asm.FnGetCurrentTaskBtf:          nil, // TODO
		asm.FnBprmOptsSet:                nil, // TODO
		asm.FnKtimeGetCoarseNs:           linuxHelperGetKTimeNs,
		asm.FnImaInodeHash:               nil, // TODO
		asm.FnSockFromFile:               nil, // TODO
		asm.FnCheckMtu:                   nil, // TODO
		asm.FnForEachMapElem:             nil, // TODO
		asm.FnSnprintf:                   nil, // TODO
		asm.FnSysBpf:                     nil, // TODO
		asm.FnBtfFindByNameKind:          nil, // TODO
		asm.FnSysClose:                   nil, // TODO
		asm.FnTimerInit:                  nil, // TODO
		asm.FnTimerSetCallback:           nil, // TODO
		asm.FnTimerStart:                 nil, // TODO
		asm.FnTimerCancel:                nil, // TODO
		asm.FnGetFuncIp:                  nil, // TODO
		asm.FnGetAttachCookie:            nil, // TODO
		asm.FnTaskPtRegs:                 nil, // TODO
	}
	// A list of helper functions which can be replayed, functions not in this list MUST be emulated due to side
	// effects.
	replayableHelpers = []bool{
		0:                                false, // 0 is not a valid helper function
		asm.FnMapLookupElem:              false,
		asm.FnMapUpdateElem:              false,
		asm.FnMapDeleteElem:              false,
		asm.FnProbeRead:                  true,
		asm.FnKtimeGetNs:                 true,
		asm.FnTracePrintk:                false,
		asm.FnGetPrandomU32:              true,
		asm.FnGetSmpProcessorId:          true,
		asm.FnSkbStoreBytes:              false,
		asm.FnL3CsumReplace:              false,
		asm.FnL4CsumReplace:              false,
		asm.FnTailCall:                   false,
		asm.FnCloneRedirect:              false,
		asm.FnGetCurrentPidTgid:          true,
		asm.FnGetCurrentUidGid:           true,
		asm.FnGetCurrentComm:             true,
		asm.FnGetCgroupClassid:           true,
		asm.FnSkbVlanPush:                false,
		asm.FnSkbVlanPop:                 false,
		asm.FnSkbGetTunnelKey:            false, // TODO
		asm.FnSkbSetTunnelKey:            false, // TODO
		asm.FnPerfEventRead:              true,
		asm.FnRedirect:                   true,
		asm.FnGetRouteRealm:              true,
		asm.FnPerfEventOutput:            false,
		asm.FnSkbLoadBytes:               true,
		asm.FnGetStackid:                 true,
		asm.FnCsumDiff:                   true,
		asm.FnSkbGetTunnelOpt:            false, // TODO
		asm.FnSkbSetTunnelOpt:            false, // TODO
		asm.FnSkbChangeProto:             false,
		asm.FnSkbChangeType:              false,
		asm.FnSkbUnderCgroup:             true,
		asm.FnGetHashRecalc:              true,
		asm.FnGetCurrentTask:             false, // TODO
		asm.FnProbeWriteUser:             false, // TODO
		asm.FnCurrentTaskUnderCgroup:     true,
		asm.FnSkbChangeTail:              false,
		asm.FnSkbPullData:                false,
		asm.FnCsumUpdate:                 false,
		asm.FnSetHashInvalid:             false,
		asm.FnGetNumaNodeId:              true,
		asm.FnSkbChangeHead:              false,
		asm.FnXdpAdjustHead:              false,
		asm.FnProbeReadStr:               false, // TODO
		asm.FnGetSocketCookie:            true,
		asm.FnGetSocketUid:               true,
		asm.FnSetHash:                    false,
		asm.FnSetsockopt:                 false,
		asm.FnSkbAdjustRoom:              false,
		asm.FnRedirectMap:                true, // TODO shouldn't we store the redirect info using an emulated func?
		asm.FnSkRedirectMap:              true, // TODO shouldn't we store the redirect info using an emulated func?
		asm.FnSockMapUpdate:              false,
		asm.FnXdpAdjustMeta:              false,
		asm.FnPerfEventReadValue:         false, // TODO
		asm.FnPerfProgReadValue:          false, // TODO
		asm.FnGetsockopt:                 false,
		asm.FnOverrideReturn:             false, // TODO
		asm.FnSockOpsCbFlagsSet:          false,
		asm.FnMsgRedirectMap:             true,  // TODO shouldn't we store the redirect info using an emulated func?
		asm.FnMsgApplyBytes:              false, // TODO
		asm.FnMsgCorkBytes:               false,
		asm.FnMsgPullData:                false,
		asm.FnBind:                       false, // TODO
		asm.FnXdpAdjustTail:              false,
		asm.FnSkbGetXfrmState:            false,
		asm.FnGetStack:                   false, // TODO
		asm.FnSkbLoadBytesRelative:       true,
		asm.FnFibLookup:                  false, // TODO
		asm.FnSockHashUpdate:             false,
		asm.FnMsgRedirectHash:            true, // TODO shouldn't we store the redirect info using an emulated func?
		asm.FnSkRedirectHash:             true, // TODO shouldn't we store the redirect info using an emulated func?
		asm.FnLwtPushEncap:               false,
		asm.FnLwtSeg6StoreBytes:          false,
		asm.FnLwtSeg6AdjustSrh:           false,
		asm.FnLwtSeg6Action:              false,
		asm.FnRcRepeat:                   true,
		asm.FnRcKeydown:                  true,
		asm.FnSkbCgroupId:                true,
		asm.FnGetCurrentCgroupId:         true,
		asm.FnGetLocalStorage:            false,
		asm.FnSkSelectReuseport:          false,
		asm.FnSkbAncestorCgroupId:        true,
		asm.FnSkLookupTcp:                false, // TODO
		asm.FnSkLookupUdp:                false, // TODO
		asm.FnSkRelease:                  false, // TODO
		asm.FnMapPushElem:                false,
		asm.FnMapPopElem:                 false,
		asm.FnMapPeekElem:                false,
		asm.FnMsgPushData:                false,
		asm.FnMsgPopData:                 false,
		asm.FnRcPointerRel:               true,
		asm.FnSpinLock:                   false,
		asm.FnSpinUnlock:                 false,
		asm.FnSkFullsock:                 false, // TODO
		asm.FnTcpSock:                    false, // TODO
		asm.FnSkbEcnSetCe:                false, // TODO
		asm.FnGetListenerSock:            false, // TODO
		asm.FnSkcLookupTcp:               false, // TODO
		asm.FnTcpCheckSyncookie:          true,
		asm.FnSysctlGetName:              false, // TODO
		asm.FnSysctlGetCurrentValue:      false, // TODO
		asm.FnSysctlGetNewValue:          false, // TODO
		asm.FnSysctlSetNewValue:          true,
		asm.FnStrtol:                     true,
		asm.FnStrtoul:                    true,
		asm.FnSkStorageGet:               false,
		asm.FnSkStorageDelete:            false,
		asm.FnSendSignal:                 true,
		asm.FnTcpGenSyncookie:            false,
		asm.FnSkbOutput:                  false,
		asm.FnProbeReadUser:              false, // TODO
		asm.FnProbeReadKernel:            false, // TODO
		asm.FnProbeReadUserStr:           false, // TODO
		asm.FnProbeReadKernelStr:         false, // TODO
		asm.FnTcpSendAck:                 true,
		asm.FnSendSignalThread:           true,
		asm.FnJiffies64:                  true,
		asm.FnReadBranchRecords:          false, // TODO
		asm.FnGetNsCurrentPidTgid:        false, // TODO
		asm.FnXdpOutput:                  false,
		asm.FnGetNetnsCookie:             true,
		asm.FnGetCurrentAncestorCgroupId: true,
		asm.FnSkAssign:                   true,
		asm.FnKtimeGetBootNs:             true,
		asm.FnSeqPrintf:                  true,
		asm.FnSeqWrite:                   true,
		asm.FnSkCgroupId:                 true,
		asm.FnSkAncestorCgroupId:         true,
		asm.FnRingbufOutput:              false,
		asm.FnRingbufReserve:             false,
		asm.FnRingbufSubmit:              false,
		asm.FnRingbufDiscard:             false,
		asm.FnRingbufQuery:               false,
		asm.FnCsumLevel:                  false, // TODO
		asm.FnSkcToTcp6Sock:              false, // TODO
		asm.FnSkcToTcpSock:               false, // TODO
		asm.FnSkcToTcpTimewaitSock:       false, // TODO
		asm.FnSkcToTcpRequestSock:        false, // TODO
		asm.FnSkcToUdp6Sock:              false, // TODO
		asm.FnGetTaskStack:               false, // TODO
		asm.FnLoadHdrOpt:                 false, // TODO
		asm.FnStoreHdrOpt:                true,
		asm.FnReserveHdrOpt:              true,
		asm.FnInodeStorageGet:            false,
		asm.FnInodeStorageDelete:         false,
		asm.FnDPath:                      false, // TODO
		asm.FnCopyFromUser:               false, // TODO
		asm.FnSnprintfBtf:                true,
		asm.FnSeqPrintfBtf:               true,
		asm.FnSkbCgroupClassid:           true,
		asm.FnRedirectNeigh:              true,
		asm.FnPerCpuPtr:                  false,
		asm.FnThisCpuPtr:                 false,
		asm.FnRedirectPeer:               true,
		asm.FnTaskStorageGet:             false,
		asm.FnTaskStorageDelete:          false,
		asm.FnGetCurrentTaskBtf:          false, // TODO
		asm.FnBprmOptsSet:                true,
		asm.FnKtimeGetCoarseNs:           true,
		asm.FnImaInodeHash:               false, // TODO
		asm.FnSockFromFile:               false, // TODO
		asm.FnCheckMtu:                   true,
		asm.FnForEachMapElem:             false,
		asm.FnSnprintf:                   false, // TODO
		asm.FnSysBpf:                     true,
		asm.FnBtfFindByNameKind:          true,
		asm.FnSysClose:                   true,
		asm.FnTimerInit:                  false,
		asm.FnTimerSetCallback:           false,
		asm.FnTimerStart:                 false,
		asm.FnTimerCancel:                false,
		asm.FnGetFuncIp:                  true,
		asm.FnGetAttachCookie:            true,
		asm.FnTaskPtRegs:                 false, // TODO
		// bpf_get_branch_snapshot
		asm.BuiltinFunc(176): false, // TODO
		// bpf_trace_vprintk
		asm.BuiltinFunc(177): false, // TODO
		// bpf_skc_to_unix_sock
		asm.BuiltinFunc(178): false, // TODO
		// bpf_kallsyms_lookup_name
		asm.BuiltinFunc(179): true,
		// bpf_find_vma
		asm.BuiltinFunc(180): false,
		// bpf_loop
		asm.BuiltinFunc(181): false,
		// bpf_strncmp
		asm.BuiltinFunc(182): true,
		// bpf_get_func_arg
		asm.BuiltinFunc(183): false, // TODO
		// bpf_get_func_ret
		asm.BuiltinFunc(184): false, // TODO
		// bpf_get_func_arg_cnt
		asm.BuiltinFunc(185): true,
		// bpf_get_retval
		asm.BuiltinFunc(186): true,
		// bpf_set_retval
		asm.BuiltinFunc(187): true,
	}
)

func syscallErr(errNo syscall.Errno) uint64 {
	return uint64(int64(0) - int64(errNo))
}

func regToMap(p *Process, reg asm.Register) (LinuxMap, error) {
	// Deref the map pointer to get the actual map object
	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.Get(reg)))
	if !found {
		return nil, fmt.Errorf("invalid map pointer in %s, can't find entry in memory controller", reg)
	}

	lm, ok := entry.Object.(LinuxMap)
	if !ok {
		// There are situations, like when using map-in-map types where we will get a double pointer to a BPF map
		// So lets attempts to dereference once more
		if vmMem, ok := entry.Object.(VMMem); ok {
			addr, err := vmMem.Load(off, asm.Word)
			if err != nil {
				return nil, fmt.Errorf("Error while attempting to deref dubbel map ptr")
			}

			entry, _, found = p.VM.MemoryController.GetEntry(uint32(addr))
			if !found {
				return nil, fmt.Errorf("invalid doubel map pointer in %s, can't find entry in memory controller", reg)
			}

			lm, ok = entry.Object.(LinuxMap)
			if !ok {
				return nil, fmt.Errorf("%s doesn't contain pointer or dubbel pointer to a LinuxMap", reg)
			}
		} else {
			return nil, fmt.Errorf("%s doesn't contain pointer to a LinuxMap", reg)
		}
	}

	return lm, nil
}

func derefMapKey(p *Process, register uint64, size uint32) ([]byte, error) {
	addr := uint32(register)

	// Deref the key to get the actual key value
	keyMem, off, found := p.VM.MemoryController.GetEntry(addr)
	if !found {
		return nil, fmt.Errorf("key unknown to memory controller: 0x%x", addr)
	}

	vmMem, ok := keyMem.Object.(VMMem)
	if !ok {
		return nil, fmt.Errorf("key points to non-vm memory: 0x%x", addr)
	}

	// Read x bytes at the given key pointer, x being the key size indicated by the map spec
	keyVal := make([]byte, size)
	err := vmMem.Read(off, keyVal)
	if err != nil {
		return nil, fmt.Errorf("deref key ptr: %w", err)
	}

	return keyVal, nil
}

func linuxHelperCantEmulate(p *Process) error {
	return errors.New("This helper isn't emulated, captured context required")
}

func linuxHelperMapLookupElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}

	keyVal, err := derefMapKey(p, p.Registers.R2, lm.GetSpec().KeySize)
	if err != nil {
		return err
	}

	valPtr, err := lm.Lookup(keyVal, p.CPUID())
	if err != nil {
		var sysErr syscall.Errno
		if !errors.As(err, &sysErr) {
			return fmt.Errorf("LinuxMap lookup: %w", err)
		}
		p.Registers.R0 = uint64(sysErr)
		return nil
	}

	p.Registers.R0 = uint64(valPtr)

	return nil
}

func linuxHelperMapUpdateElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key, R3 = ptr to value, R4 = flags
	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}

	lmu, ok := lm.(LinuxMapUpdater)
	if !ok {
		return fmt.Errorf("given LinuxMap can't be updated")
	}

	keyVal, err := derefMapKey(p, p.Registers.R2, lm.GetSpec().KeySize)
	if err != nil {
		return err
	}

	// Deref the value to get the actual value value
	value := uint32(p.Registers.R3)
	valMem, off, found := p.VM.MemoryController.GetEntry(value)
	if !found {
		return fmt.Errorf("value unknown to memory controller: 0x%x", value)
	}

	vmMem, ok := valMem.Object.(VMMem)
	if !ok {
		return fmt.Errorf("value points to non-vm memory: 0x%x", value)
	}

	// Read x bytes at the given value pointer, x being the value size indicated by the map spec
	valVal := make([]byte, lm.GetSpec().ValueSize)
	err = vmMem.Read(off, valVal)
	if err != nil {
		return fmt.Errorf("deref value ptr: %w", err)
	}

	err = lmu.Update(keyVal, valVal, uint32(p.Registers.R4), p.CPUID())
	if err != nil {
		var sysErr syscall.Errno
		if !errors.As(err, &sysErr) {
			return fmt.Errorf("LinuxMap update: %w", err)
		}
		p.Registers.R0 = uint64(sysErr)
		return nil
	}

	p.Registers.R0 = 0
	return nil
}

func linuxHelperMapDeleteElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}
	lmd, ok := lm.(LinuxMapDeleter)
	if !ok {
		return fmt.Errorf("can't delete from given LinuxMap")
	}

	keyVal, err := derefMapKey(p, p.Registers.R2, lm.GetSpec().KeySize)
	if err != nil {
		return err
	}
	err = lmd.Delete(keyVal)
	if err != nil {
		var sysErr syscall.Errno
		if !errors.As(err, &sysErr) {
			return fmt.Errorf("LinuxMap delete: %w", err)
		}
		p.Registers.R0 = uint64(sysErr)
		return nil
	}

	p.Registers.R0 = 0
	return nil
}

func linuxHelperGetKTimeNs(p *Process) error {
	// Note: this helper should subtract time the system was suspended, but we don't do that at the moment.
	// TODO can we even get access to a suspended-time-counter in userspace? Is this that critical?
	bootTime := p.VM.settings.Emulator.(*LinuxEmulator).settings.TimeOfBoot
	p.Registers.R0 = uint64(time.Since(bootTime))
	return nil
}

// bpf_get_prandom_u32
func linuxHelperGetPRandomU32(p *Process) error {
	p.Registers.R0 = uint64(p.VM.settings.Emulator.(*LinuxEmulator).rng.Uint32())
	return nil
}

// bpf_get_smp_processor_id
func linuxHelperGetSmpProcessorID(p *Process) error {
	p.Registers.R0 = uint64(p.CPUID())
	return nil
}

// bpf_skb_store_bytes
func linuxHelperSKBStoreBytes(p *Process) error {
	// R1 = ctx (*sk_buff), R2 = offset, R3 = ptr to value, R4 = len, R5 = flags
	entry, _, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R1))
	if !found {
		return fmt.Errorf("mem ctl, didn't find sk_buff at 0x%08X", p.Registers.R1)
	}

	buf, ok := entry.Object.(*SKBuff)
	if !ok {
		return fmt.Errorf("R1 is not a valid sk_buff")
	}

	// TODO handle flags (BPF_F_RECOMPUTE_CSUM, BPF_F_INVALIDATE_HASH)

	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R3))
	if !found {
		return fmt.Errorf("mem ctl, didn't find vm-mem at 0x%08X", p.Registers.R3)
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("R3 is not vm-mem")
	}

	value := make([]byte, p.Registers.R4)
	err := vmmem.Read(off, value)
	if err != nil {
		return fmt.Errorf("vm-mem read: %w", err)
	}

	err = buf.pkt.Write(uint32(p.Registers.R2), value)
	if err != nil {
		return fmt.Errorf("pkt write: %w", err)
	}

	p.Registers.R0 = 0

	return nil
}

func linuxHelperTailcall(p *Process) error {
	// R1 = ctx, R2 = ptr to the prog array map, R3 = uint32 key

	var pastTailcalls int
	if i := p.EmulatorValues[LinuxEmuProcValKeyTailcalls]; i != nil {
		var ok bool
		pastTailcalls, ok = i.(int)
		if !ok {
			pastTailcalls = 0
		}
	}

	// If we have exceeded the configured max amount of tailcalls, deny execution of another.
	// We do this to emulate the behavior of Linux.
	if pastTailcalls >= p.VM.settings.Emulator.(*LinuxEmulator).settings.MaxTailCalls {
		p.Registers.R0 = syscallErr(syscall.EPERM)
		return nil
	}

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R2)
	if err != nil {
		return err
	}

	if lm.GetSpec().Type != ebpf.ProgramArray || lm.GetSpec().KeySize != 4 {
		return fmt.Errorf("R1 is not a program array map")
	}

	progArr, ok := lm.(*LinuxArrayMap)
	if !ok {
		return fmt.Errorf("R1 is not a program array map")
	}

	// For the tailcall helper the key is passed directly, not as pointer
	key := make([]byte, 4)
	GetNativeEndianness().PutUint32(key, uint32(p.Registers.R3))

	// Lookup should return a pointer into the prog array values
	progAddrPtr, err := progArr.Lookup(key, p.CPUID())
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}

	// Deref the pointer to get the prog array VMMem
	entry, off, found := p.VM.MemoryController.GetEntry(progAddrPtr)
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("prog array lookup returned pointer to non-vm-memory")
	}

	// Get the program address from the array
	progAddr, err := vmmem.Load(off, asm.Word)
	if !ok {
		return fmt.Errorf("prog addr lookup: %w", err)
	}

	// Deref it to get the *ebpf.ProgramSpec
	entry, _, found = p.VM.MemoryController.GetEntry(uint32(progAddr))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	prog, ok := entry.Object.(*ebpf.ProgramSpec)
	if !ok {
		// If the address resolves to something other than a program
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	// Change the program
	p.Program = prog
	// Set the PC to -1, since after returning from the helper the PC is incremented, this will result in a PC of 0
	// so the next instruction to be executed is the first of the given program.
	p.Registers.PC = -1

	// Increment the tailcall count
	pastTailcalls++
	p.EmulatorValues[LinuxEmuProcValKeyTailcalls] = pastTailcalls

	return nil
}

const (
	// Mask containing the desired CPU index
	bpfFIndexMask = 0xffffffff
	// If masked flags is equal to bpfFCurrentCPU, use the current CPU as index
	bpfFCurrentCPU = bpfFIndexMask
	// Mask used to communicate the length of the ctx, for use in bpf_xdp_event_output and bpf_skb_event_output
	// bpfFCtxLenMask = 0xfffff << 32
)

func linuxHelperEventOutput(p *Process) error {
	// R1 = ctx, R2 = ptr to the perf array map, R3 = uint64 flags, R4 = ptr to value, R5 = uint64 size

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R2)
	if err != nil {
		return err
	}

	m, ok := lm.(*LinuxPerfEventArrayMap)
	if !ok {
		return fmt.Errorf("R1 is not a perf event array map")
	}

	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R4))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("prog array lookup returned pointer to non-vm-memory")
	}

	val := make([]byte, p.Registers.R5)
	err = vmmem.Read(off, val)
	if err != nil {
		return fmt.Errorf("vmmem read: %w", err)
	}

	idx := p.Registers.R3 & bpfFIndexMask
	if idx == bpfFCurrentCPU {
		idx = uint64(p.CPUID())
	}

	if int(idx) < 0 {
		return fmt.Errorf("invalid cpuid: %d", idx)
	}

	err = m.Push(val, int(idx))
	if err != nil {
		if syserr, ok := err.(syscall.Errno); ok {
			p.Registers.R0 = syscallErr(syserr)
			return nil
		}

		return fmt.Errorf("push: %w", err)
	}

	return nil
}

func linuxHelperXDPAdjustTail(p *Process) error {
	delta := int64(p.Registers.R2)

	// R1 = ptr to ctx, R2 = delta
	entry, _, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R1))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	xdpmd, ok := entry.Object.(*PlainMemory)
	if !ok {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	// The XDP_MD ctx is 20 bytes, this is a sanity check
	if len(xdpmd.Backing) != 20 {
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	dataAddr, err := xdpmd.Load(0, asm.Word)
	if err != nil {
		return err
	}

	dataEndAddr, err := xdpmd.Load(4, asm.Word)
	if err != nil {
		return err
	}

	entry, offset, found := p.VM.MemoryController.GetEntry(uint32(dataEndAddr))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	pkt, ok := entry.Object.(*PlainMemory)
	if !ok {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	curSize := dataEndAddr - dataAddr
	availableTailroom := len(pkt.Backing) - int(offset)
	if delta >= 0 {
		// If the users wants to grow beyond the available tailroom
		if delta > int64(availableTailroom) {
			p.Registers.R0 = syscallErr(syscall.E2BIG)
			return nil
		}
	} else {
		// If the user wants to shrink beyond start of packet
		if -delta >= int64(curSize) {
			p.Registers.R0 = syscallErr(syscall.E2BIG)
			return nil
		}
	}

	newDataEndAddr := int64(dataEndAddr) + delta

	err = xdpmd.Store(4, uint64(newDataEndAddr), asm.Word)
	if err != nil {
		return fmt.Errorf("update data end: %w", err)
	}

	return nil
}

func linuxHelperMapPushElem(p *Process) error {
	// R1 = ptr to map, R2 = ptr to value, R3 = flags

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}
	pm, ok := lm.(LinuxMapPusher)
	if !ok {
		return fmt.Errorf("given map is not a LinuxMapPusher")
	}

	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R2))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("value is pointer to non-vm-memory")
	}

	val := make([]byte, lm.GetSpec().ValueSize)
	err = vmmem.Read(off, val)
	if err != nil {
		return fmt.Errorf("vmmem read: %w", err)
	}

	err = pm.Push(val, p.CPUID())
	if err != nil {
		if syserr, ok := err.(syscall.Errno); ok {
			p.Registers.R0 = syscallErr(syserr)
			return nil
		}

		return fmt.Errorf("push: %w", err)
	}

	p.Registers.R0 = 0
	return nil
}

func linuxHelperMapPopElem(p *Process) error {
	// R1 = ptr to map, R2 = ptr to value

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}
	pm, ok := lm.(LinuxMapPopper)
	if !ok {
		return fmt.Errorf("given map is not a LinuxMapPopper")
	}

	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R2))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("value is pointer to non-vm-memory")
	}

	val, err := pm.Pop(p.CPUID())
	if err != nil {
		if syserr, ok := err.(syscall.Errno); ok {
			p.Registers.R0 = syscallErr(syserr)
			return nil
		}

		return fmt.Errorf("pop: %w", err)
	}

	// Map empty
	if val == 0 {
		p.Registers.R0 = syscallErr(syscall.ENOMSG)
		return nil
	}

	err = vmmem.Store(off, uint64(val), asm.Word)
	if err != nil {
		return fmt.Errorf("vmmem store: %w", err)
	}

	p.Registers.R0 = 0
	return nil
}

func linuxHelperMapPeekElem(p *Process) error {
	// R1 = ptr to map, R2 = ptr to value

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}
	_, ok := lm.(LinuxMapPopper)
	if !ok {
		return fmt.Errorf("given map is not a LinuxMapPopper")
	}

	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R2))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("value is pointer to non-vm-memory")
	}

	val, err := lm.Lookup([]byte{0, 0, 0, 0}, p.CPUID())
	if err != nil {
		if syserr, ok := err.(syscall.Errno); ok {
			p.Registers.R0 = syscallErr(syserr)
			return nil
		}

		return fmt.Errorf("peek: %w", err)
	}

	// Map empty
	if val == 0 {
		p.Registers.R0 = syscallErr(syscall.ENOMSG)
		return nil
	}

	err = vmmem.Store(off, uint64(val), asm.Word)
	if err != nil {
		return fmt.Errorf("vmmem store: %w", err)
	}

	p.Registers.R0 = 0
	return nil
}
