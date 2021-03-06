# Mimic (eBPF userspace emulator)
[![Go Reference](https://pkg.go.dev/badge/github.com/dylandreimerink/mimic.svg)](https://pkg.go.dev/github.com/dylandreimerink/mimic)

Mimic is a eBPF virtual machine and emulator which runs in userspace. Mimic attempts to 'mimic' the eBPF machinery we find in the Linux kernel, as well as other possible implementation/environments. 

## Goals / use cases

Mimics main purpose is to serve as a backend for the [edb](https://github.com/dylandreimerink/edb) eBPF debugger, which is needed since we can't interrupt the kernel and "step" through its execution like we can in userspace. 

Secondly, running eBPF programs typically requires Linux, so developing on a machine which itself doesn't have eBPF support makes testing difficult. Since Mimic is written in Go, developers should be able to run eBPF programs on their own machine.

Third, Mimic might be useful for embedding external/untrusted programs in Go applications, or as a plugin system. This is what eBPF is designed to do after all, except in the Linux kernel. It should be noted that this is not a JIT-ed implementation, so it is not as fast as native code. But perhaps it can compete with [WASM](https://github.com/suborbital/reactr), [JS](https://github.com/robertkrimen/otto) and [LUA](https://github.com/Shopify/go-lua)

## Getting started

Just like running eBPF in a Linux kernel, we need to do a few steps to setup, most of which will be familiar.

```go
// Create a new Linux emulator, which handles some Linux specific eBPF features like maps.
emu := &mimic.LinuxEmulator{}
// Create a VM, which can spawn multiple processes, we pass the emulator to the VM, the VM will call the emulator
// at certain points, namely when loading programs and for helper functions.
vm := mimic.NewVM(mimic.VMOptEmulator(emu))

// Parse an ELF file containing programs and maps
coll, err := ebpf.LoadCollectionSpec("./example-ebpf-elf-file")
if err != nil {
    panic(err)
}

// Get a map specification from the collection(this is just information about the map type)
exampleMapSpec := coll.Maps["example_map"]
// Get an emulated map based on the spec(which can actually store data)
exampleMap, err := mimic.MapSpecToLinuxMap(exampleMapSpec)
if err != nil {
    panic(err)
}

// Register the emulated map with the emulator.
err = emu.AddMap(exampleMap)
if err != nil {
    panic(err)
}

// Note: After registering the map, it will be initialized, you can now modify it.

// Get and load the program specification.
prog := coll.Programs["example_prog"]
progID, err := vm.AddProgram(prog)
if err != nil {
    panic(err)
}

// Open the program context file.
f, err := os.Open("./example.ctx.json")
if err != nil {
    panic(err)
}

// Unmarshal the JSON into an actual context object, more about what a context is and its JSON format in the
// "Context" readme section.
ctx, err := mimic.UnmarshalContextJSON(f)
if err != nil {
    panic(err)
}

// Start a new process by providing the unique ID of the loaded program and a context. This links `ctx` to the process
// until p is cleaned up and can't be used by other processes.
p, err := vm.NewProcess(progID, ctx)
if err != nil {
    panic(err)
}

// Run the instance of the program. Alternatively, one can manually execute each program instruction via the p.Step()
// function.
err = p.Run(context.Background())

// Note: after running a process, one can inspect maps, memory, registers and the context to get the program results

// Cleanup the process, this frees memory associated with the process, p should not be stored or used after calling
// cleanup. The `ctx` that was attached is also cleaned up and can now be re-used.
err = p.Cleanup()
```

## VM vs Emulator

eBPF is no longer Linux specific([eBPF for windows](https://github.com/Microsoft/ebpf-for-windows)). Now the [eBPF instruction](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html) set is well defined as must be constant across all platforms(perhaps with the exception of legacy cBPF instructions for packet access). However, the Linux eBPF subsystem makes use of a lot of maps, some if which are generic, but most of which are very specialized and aimed at Linux specific features like cGroups or LSM.

To be able to support all use cases and emulator multiple platforms/environments, Mimic splits functionality into two parts(reals). The "Virtual Machine" which is responsible for all generic features(Instructions, Registers, Memory, Processes). The "Emulator" is interchangeable and provides platform/environment specific features(Helper functions/Maps/Some other construct), besides a Linux emulator we can have a Windows emulator and users of Mimic might even implement their own emulator with custom helper functions specific to their needs.

## Thread safety / concurrent execution

Mimic considers two different levels of safety and race-conditions. The first is race-conditions in Go-land, meaning in the VM or emulator itself, cases like concurrent access to maps. The second level is in eBPF-land, which would be concurrent reads and writes to the same map key. The emulator allocates memory in the form of `[]byte` which will not change in size during their lifetime, therefor race-conditions in the contents of these allocations are considered "safe" from a emulator perspective. This is very much like the behavior of the Linux kernel itself.

So the vm/emulator is thread safe, but the eBPF programs not necessary, running multiple processes concurrently might give cause race-conditions in the eBPF programs, eBPF programs are responsible for their own race-conditions and must guard against them using eBPF mechanism like per-CPU maps and emulated spin locks.

## Contexts

When the Linux kernel invokes a eBPF program it will pass it arguments also called a context. The type of the context depends on the program type and even where it is attached. An XDP program will get a `*xdp_md` passed while a socket program will get a `*sk_buff`. So when we start a eBPF program we also need to pass in a context.

Just passing in some arguments is enough for some programs, but more complex programs often make extensive use of helper functions such as `bpf_get_current_pid_tgid` or `bpf_probe_read` which return memory from the kernel. Therefor the context also contains data which will be used to return environment data to the eBPF calls.

Any Go struct which implements `mimic.Context` can be used as a context. The `mimic.UnmarshalContextJSON` function can be used to unmarshal JSON files into the contexts types provided by `mimic`. The `mimic.RegisterContextUnmarshaller` function can be used to register additional context types, so all context parsing can work via a single function.

### Generic context

The goal of the `generic` context type is to provide a context which should cover all situations. It enabled users to craft any data structure. This makes it also very verbose, which is why for some program types, more specialized contexts types are implemented.

<!-- TODO explain the structure and features -->

```json
{
    "name": "{name of the context}",
    "type": "generic",
    "ctx": {
        "registers": {
            "r1": "{name of a memory section}",
            "r2": "{name of a memory section}",
            "r3": "{name of a memory section}",
            "r4": "{name of a memory section}",
            "r5": "{name of a memory section}"
        },
        "memory": [
            {
                "name": "{Name of this piece of memory}",
                "type": "{block|ptr|struct|int}",
                "value": "{type dependant value}"
            },
            {
                "name": "{block of memory is just a collection of bytes}",
                "type": "block",
                "value": {
                    "value": "{base64 encoded string}",
                    "byteorder": "{optional byte order(big-endian|be|little-endian|le)}"
                }
            },
            {
                "name": "{pointer points at an offset within another memory section}",
                "type": "ptr",
                "value": {
                    "memory": "{name of the memory block we point to}",
                    "offset": 20,
                    "size": 32
                }
            },
            {
                "name": "{struct is a memory structure}",
                "type": "struct",
                "value": [
                    {
                        "name": "{field name}",
                        "memory": "{name of other memory}"
                    },
                    {
                        "name": "{field name}",
                        "memory": "{name of other memory}"
                    }
                ]
            },
            {
                "name": "{Name of this integer}",
                "type": "int",
                "value": {
                    "value": 123,
                    "size": 8
                }
            }
        ],
        "emulator": {
            "key": "this can be anything. The schema will be determined by the specific emulator",
            "other-key": "these k/v pairs are not loaded into the VM's memory, but can reference it"
        }
    }
}
```

### XDP_MD

<!-- TODO add XDP_MD explication -->
<!-- TODO add JSON example -->

### sk_buff

<!-- TODO add sk_buff explication -->
<!-- TODO add JSON example -->

### Captured context

A captured context is a wrapper around another context type to add "captured" helper data to it. The idea being that it is impossible to emulate a number of helper calls. Take `bpf_get_current_comm` for example, which contains the name of the current executable which would have to be supplied by the user, it is not something we can emulate. The captured context allows users to supply the result of helper calls via the context. The primary use case for this is to reply captured helper call responses from actual transactions.

This is an example of a captured context:
```json
{
    "name": "0 (2022-03-15 21:08:31.25219138 +0100 CET m=+7.724144727)",
    "type": "captured",
    "ctx": {
      "subContext": {
        "name": "0 (2022-03-15 21:08:31.25219138 +0100 CET m=+7.724144727)",
        "type": "generic",
        "ctx": {
          "registers": {},
          "memory": null,
          "emulator": {}
        }
      },
      "helperCalls": {
        "16": [
          {
            "helperFn": 16,
            "params": [
              {
                "reg": 1,
                "value": 18446656970732715112
              },
              {
                "reg": 2,
                "value": 16
              }
            ],
            "results": [
              {
                "reg": 0,
                "value": 0
              },
              {
                "reg": 1,
                "value": "cGhwLWZwbQAAAAAAAAAAAA=="
              }
            ]
          }
        ],
        "6": [
          {
            "helperFn": 6,
            "params": [
              {
                "reg": 1,
                "value": 18446613223656132368
              },
              {
                "reg": 2,
                "value": 3
              },
              {
                "reg": 3,
                "value": 18446656970732715112
              }
            ],
            "results": [
              {
                "reg": 0,
                "value": 7
              }
            ]
          }
        ]
      }
    }
  }
```

## Features / TODO

eBPF is complex, the Linux kernel is complex, thus so is an emulator. This is a list of features which we might want to add but haven't yet. Contributions are welcome. 

Note: Marked list items were on the list, but have since been implemented.

**Project quality**

- [x] Linting
- [X] CI
- [ ] Decent unit test coverage
- [x] Comments on all exported structs for GoDoc generation
- [ ] Usage examples
- [ ] Linux selftest mirroring (if we execute the linux eBPF selftests and get a positive result, can can conclude that the implementation matches)
- [ ] Benchmarking

**Generic features**

- [x] Process schedulers
  - [x] Per-CPU scheduler. Running eBPF processes on a worker pool no larger than the amount of logical CPU's. Theoretically the fastest for CPU heavy workloads.
  - [ ] Naive scheduling. Running each process in a Goroutine, mostly useful for programs which don't rely on Per-CPU maps and are I/O heavy or blocking.
- [x] `sk_buff` context. The Linux `sk_buff` structure is very complex, and would be hard to craft with the generic context. Making a purpose built context type for it seems logical.

**eBPF Instructions**

- [ ] Atomic add
- [ ] Atomic and
- [ ] Atomic or
- [ ] Atomic xor
- [ ] Atomic exchange
- [ ] Atomic compare and exchange
- [x] Packet access

**Mechanisms**

- [X] BPF-to-BPF function calls
- [X] Tailcalling (Switching of the current program)

**Linux helper functions**

| helper                             | Emulated | Captured context replay | commend                                                     |
| ---------------------------------- | -------- | ----------------------- | ----------------------------------------------------------- |
| bpf_lookup_element                 | ???        | ???                       |
| bpf_lookup_element                 | ???        | ???                       |
| bpf_update_element                 | ???        | ???                       |
| bpf_delete_element                 | ???        | ???                       |
| bpf_probe_read                     | N/A      | ???                       |
| bpf_ktime_get_ns                   | ???        | ???                       |
| bpf_trace_printk                   | ???        | ???                       | TODO add trace output                                       |
| bpf_get_prandom_u32                | ???        | ???                       |
| bpf_get_smp_processor_id           | ???        | ???                       |
| bpf_skb_store_bytes                | ???        | ???                       |
| bpf_l3_csum_replace                | ???        | ???                       | Replay returns status code, but doesn't modify sk_buff      |
| bpf_l4_csum_replace                | ???        | ???                       | Replay returns status code, but doesn't modify sk_buff      |
| bpf_tail_call                      | ???        | N/A                     |
| bpf_clone_redirect                 | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_get_current_pid_tgid           | N/A      | ???                       |
| bpf_get_current_uid_gid            | N/A      | ???                       |
| bpf_get_current_comm               | N/A      | ???                       |
| bpf_get_cgroup_classid             | N/A      | ???                       |
| bpf_skb_vlan_push                  | ???        | ???                       |
| bpf_skb_vlan_pop                   | ???        | ???                       |
| bpf_skb_get_tunnel_key             | N/A      | ???                       |
| bpf_skb_set_tunnel_key             | N/A      | ???                       |
| bpf_perf_event_read                | N/A      | ???                       |
| bpf_redirect                       | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_get_route_realm                | N/A      | ???                       |
| bpf_perf_event_output              | ???        | N/A                     |
| bpf_skb_load_bytes                 | ???        | ???                       |
| bpf_get_stackid                    | ???        | ???                       |
| bpf_csum_diff                      | ???        | ???                       |
| bpf_skb_get_tunnel_opt             | ???        | ???                       |
| bpf_skb_set_tunnel_opt             | ???        | ???                       | Replay returns status code, but doesn't modify sk_buff      |
| bpf_skb_change_proto               | ???        | N/A                     |
| bpf_skb_change_type                | ???        | N/A                     |
| bpf_skb_under_cgroup               | N/A      | ???                       |
| bpf_get_hash_recalc                | ???        | ???                       |
| bpf_get_current_task               | ???        | ???                       |
| bpf_probe_write_user               | ???        | ???                       |
| bpf_current_task_under_cgroup      | N/A      | ???                       |
| bpf_skb_change_tail                | ???        | N/A                     |
| bpf_skb_pull_data                  | ???        | N/A                     |
| bpf_csum_update                    | ???        | N/A                     |
| bpf_set_hash_invalid               | ???        | N/A                     |
| bpf_get_numa_node_id               | N/A      | ???                       |
| bpf_skb_change_head                | ???        | N/A                     |
| bpf_xdp_adjust_head                | ???        | N/A                     |
| bpf_probe_read_str                 | N/A      | ???                       |
| bpf_get_socket_cookie              | N/A      | ???                       |
| bpf_get_socket_uid                 | N/A      | ???                       |
| bpf_set_hash                       | ???        | N/A                     |
| bpf_setsockopt                     | ???        | N/A                     |
| bpf_skb_adjust_room                | ???        | N/A                     |
| bpf_redirect_map                   | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_sk_redirect_map                | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_sock_map_update                | ???        | N/A                     |
| bpf_xdp_adjust_meta                | ???        | N/A                     |
| bpf_perf_event_read_value          | N/A      | ???                       |
| bpf_perf_prog_read_value           | N/A      | ???                       |
| bpf_getsockopt                     | ???        | ???                       |
| bpf_override_return                | ???        | ???                       |
| bpf_sock_ops_cb_flags_set          | ???        | N/A                     |
| bpf_msg_redirect_map               | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_msg_apply_bytes                | ???        | N/A                     |
| bpf_msg_cork_bytes                 | ???        | N/A                     |
| bpf_msg_pull_data                  | ???        | N/A                     |
| bpf_bind                           | ???        | N/A                     |
| bpf_xdp_adjust_tail                | ???        | N/A                     |
| bpf_skb_get_xfrm_state             | ???        | N/A                     |
| bpf_get_stack                      | N/A      | ???                       |
| bpf_skb_load_bytes_relative        | ???        | ???                       |
| bpf_fib_lookup                     | ???        | ???                       |
| bpf_sock_hash_update               | ???        | N/A                     |
| bpf_msg_redirect_hash              | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_sk_redirect_hash               | ???        | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_lwt_push_encap                 | ???        | N/A                     |
| bpf_lwt_seg6_store_bytes           | ???        | N/A                     |
| bpf_lwt_seg6_adjust_srh            | ???        | N/A                     |
| bpf_lwt_seg6_action                | ???        | N/A                     |
| bpf_rc_repeat                      | ???        | ???                       |
| bpf_rc_keydown                     | ???        | ???                       |
| bpf_skb_cgroup_id                  | N/A      | ???                       |
| bpf_get_current_cgroup_id          | N/A      | ???                       |
| bpf_get_local_storage              | ???        | N/A                     |
| bpf_sk_select_reuseport            | ???        | N/A                     |
| bpf_skb_ancestor_cgroup_id         | ???        | ???                       |
| bpf_sk_lookup_tcp                  | ???        | ???                       |
| bpf_sk_lookup_udp                  | ???        | ???                       |
| bpf_sk_release                     | ???        | ???                       |
| bpf_map_push_elem                  | ???        | ???                       |
| bpf_map_pop_elem                   | ???        | ???                       |
| bpf_map_peek_elem                  | ???        | ???                       |
| bpf_msg_push_data                  | ???        | ???                       |
| bpf_msg_pop_data                   | ???        | ???                       |
| bpf_rc_pointer_rel                 | ???        | ???                       |
| bpf_spin_lock                      | ???        | N/A                     |
| bpf_spin_unlock                    | ???        | N/A                     |
| bpf_sk_fullsock                    | ???        | ???                       |
| bpf_tcp_sock                       | ???        | ???                       |
| bpf_skb_ecn_set_ce                 | ???        | ???                       |
| bpf_get_listener_sock              | ???        | ???                       |
| bpf_skc_lookup_tcp                 | ???        | ???                       |
| bpf_tcp_check_syncookie            | ???        | ???                       |
| bpf_sysctl_get_name                | ???        | ???                       |
| bpf_sysctl_get_current_value       | ???        | ???                       |
| bpf_sysctl_get_new_value           | ???        | ???                       |
| bpf_sysctl_set_new_value           | ???        | ???                       | Replay returns status code, but doesn't update sysctl       |
| bpf_strtol                         | ???        | ???                       |
| bpf_strtoul                        | ???        | ???                       |
| bpf_sk_storage_get                 | ???        | N/A                     |
| bpf_sk_storage_delete              | ???        | N/A                     |
| bpf_send_signal                    | ???        | ???                       |
| bpf_tcp_gen_syncookie              | ???        | N/A                     |
| bpf_skb_output                     | ???        | N/A                     |
| bpf_probe_read_user                | N/A      | ???                       |
| bpf_probe_read_kernel              | N/A      | ???                       |
| bpf_probe_read_user_str            | N/A      | ???                       |
| bpf_probe_read_kernel_str          | N/A      | ???                       |
| bpf_tcp_send_ack                   | ???        | ???                       |
| bpf_send_signal_thread             | ???        | ???                       |
| bpf_jiffies64                      | ???        | ???                       |
| bpf_read_branch_records            | N/A      | ???                       |
| bpf_get_ns_current_pid_tgid        | N/A      | ???                       |
| bpf_xdp_output                     | ???        | ???                       |
| bpf_get_netns_cookie               | N/A      | ???                       |
| bpf_get_current_ancestor_cgroup_id | N/A      | ???                       |
| bpf_sk_assign                      | N/A      | ???                       |
| bpf_ktime_get_boot_ns              | ???        | ???                       |
| bpf_seq_printf                     | ???        | ???                       |
| bpf_seq_write                      | ???        | ???                       |
| bpf_sk_cgroup_id                   | N/A      | ???                       |
| bpf_sk_ancestor_cgroup_id          | N/A      | ???                       |
| bpf_ringbuf_output                 | ???        | N/A                     |
| bpf_ringbuf_reserve                | ???        | N/A                     |
| bpf_ringbuf_submit                 | ???        | N/A                     |
| bpf_ringbuf_discard                | ???        | N/A                     |
| bpf_ringbuf_query                  | ???        | N/A                     |
| bpf_csum_level                     | ???        | N/A                     |
| bpf_skc_to_tcp6_sock               | ???        | ???                       |
| bpf_skc_to_tcp_sock                | ???        | ???                       |
| bpf_skc_to_tcp_timewait_sock       | ???        | ???                       |
| bpf_skc_to_tcp_request_sock        | ???        | ???                       |
| bpf_skc_to_udp6_sock               | ???        | ???                       |
| bpf_get_task_stack                 | ???        | ???                       |
| bpf_load_hdr_opt                   | ???        | ???                       |
| bpf_store_hdr_opt                  | ???        | ???                       | Replay returns status code, but doesn't sk_buff             |
| bpf_reserve_hdr_opt                | ???        | ???                       |
| bpf_inode_storage_get              | ???        | N/A                     |
| bpf_inode_storage_delete           | ???        | N/A                     |
| bpf_d_path                         | ???        | ???                       |
| bpf_copy_from_user                 | ???        | ???                       |
| bpf_snprintf_btf                   | ???        | ???                       |
| bpf_seq_printf_btf                 | ???        | ???                       |
| bpf_skb_cgroup_classid             | N/A      | ???                       |
| bpf_redirect_neigh                 | N/A      | ???                       | Replay returns status code, but doesn't store redirect info |
| bpf_per_cpu_ptr                    | ???        | ???                       |
| bpf_this_cpu_ptr                   | ???        | ???                       |
| bpf_redirect_peer                  | ???        | ???                       | eplay returns status code, but doesn't store redirect info  |
| bpf_task_storage_get               | ???        | N/A                     |
| bpf_task_storage_delete            | ???        | N/A                     |
| bpf_get_current_task_btf           | ???        | ???                       |
| bpf_bprm_opts_set                  | ???        | ???                       |
| bpf_ktime_get_coarse_ns            | ???        | ???                       |
| bpf_ima_inode_hash                 | ???        | ???                       |
| bpf_sock_from_file                 | ???        | ???                       |
| bpf_check_mtu                      | ???        | ???                       |
| bpf_for_each_map_elem              | ???        | N/A                     |
| bpf_snprintf                       | ???        | ???                       |
| bpf_sys_bpf                        | ???        | ???                       |
| bpf_btf_find_by_name_kind          | ???        | ???                       |
| bpf_sys_close                      | ???        | ???                       |
| bpf_timer_init                     | ???        | N/A                     |
| bpf_timer_set_callback             | ???        | N/A                     |
| bpf_timer_start                    | ???        | N/A                     |
| bpf_timer_cancel                   | ???        | N/A                     |
| bpf_get_func_ip                    | ???        | ???                       |
| bpf_get_attach_cookie              | ???        | ???                       |
| bpf_task_pt_regs                   | ???        | ???                       |
| bpf_get_branch_snapshot            | ???        | ???                       |
| bpf_trace_vprintk                  | ???        | ???                       |
| bpf_skc_to_unix_sock               | ???        | ???                       |
| bpf_kallsyms_lookup_name           | ???        | ???                       |
| bpf_find_vma                       | ???        | ???                       |
| bpf_loop                           | ???        | ???                       |
| bpf_strncmp                        | ???        | ???                       |
| bpf_get_func_arg                   | ???        | ???                       |
| bpf_get_func_ret                   | ???        | ???                       |
| bpf_get_func_arg_cnt               | ???        | ???                       |
| bpf_get_retval                     | ???        | ???                       |
| bpf_set_retval                     | ???        | ???                       |

**Linux maps**

- [x] BPF_MAP_TYPE_HASH
- [x] BPF_MAP_TYPE_ARRAY
- [x] BPF_MAP_TYPE_PROG_ARRAY (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_PERF_EVENT_ARRAY
- [x] BPF_MAP_TYPE_PERCPU_HASH
- [x] BPF_MAP_TYPE_PERCPU_ARRAY
- [ ] BPF_MAP_TYPE_STACK_TRACE
- [x] BPF_MAP_TYPE_CGROUP_ARRAY (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_LRU_HASH
- [ ] BPF_MAP_TYPE_LRU_PERCPU_HASH
- [ ] BPF_MAP_TYPE_LPM_TRIE
- [x] BPF_MAP_TYPE_ARRAY_OF_MAPS (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_HASH_OF_MAPS (covered by BPF_MAP_TYPE_HASH)
- [x] BPF_MAP_TYPE_DEVMAP (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_SOCKMAP (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_CPUMAP (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_XSKMAP (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_SOCKHASH (covered by BPF_MAP_TYPE_HASH)
- [x] BPF_MAP_TYPE_CGROUP_STORAGE (covered by BPF_MAP_TYPE_HASH)
- [x] BPF_MAP_TYPE_REUSEPORT_SOCKARRAY (covered by BPF_MAP_TYPE_ARRAY)
- [x] BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE (covered by BPF_MAP_TYPE_PERCPU_HASH)
- [x] BPF_MAP_TYPE_QUEUE
- [x] BPF_MAP_TYPE_STACK
- [x] BPF_MAP_TYPE_SK_STORAGE (covered by BPF_MAP_TYPE_HASH)
- [x] BPF_MAP_TYPE_DEVMAP_HASH (covered by BPF_MAP_TYPE_HASH)
- [x] BPF_MAP_TYPE_STRUCT_OPS (covered by BPF_MAP_TYPE_HASH)
- [ ] BPF_MAP_TYPE_RINGBUF
- [x] BPF_MAP_TYPE_INODE_STORAGE (covered by BPF_MAP_TYPE_HASH)
- [x] BPF_MAP_TYPE_TASK_STORAGE (covered by BPF_MAP_TYPE_HASH)
- [ ] BPF_MAP_TYPE_BLOOM_FILTER

**Misc**

- [ ] (optional) real map backing. The idea being that instead of emulating a map, we can use actual BPF maps of the host. It may not be able to simulate all features, disabling syscall writes on a map would also block access for the eBPF program in this case. But baring some limitations, this could allow someone to share a map between the emulator and a loader program, or a real and emulated program. 
- [ ] emulator helper customization. Allowing users to change or extend the existing Linux emulator. For example to replace the `bpf_probe_read` callback so the Host program can return its own custom memory objects, thus being able integrate the VM/Emulator with the rest of the host application.
- [ ] high-security settings on the vm. There are moments when we reuse memory(deleting map keys, tailcalls, bpf-to-bpf calls), but don't zero it out before reuse. There might be use cases, especially when running foreign code in a multi tenant environment where this might lead to security issues. Zeroing out memory can be costly, especially if the security use-case doesn't apply, so being able to enable or disable this feature with a VM setting would be nice. (Note: we currently don't zero-memory at all). (Note2: zeroing out memory should also enforce correctness for programs)