module github.com/dylandreimerink/mimic

go 1.16

replace github.com/cilium/ebpf => github.com/dylandreimerink/ebpf v0.8.1-0.20220213140259-64386bac261c

require (
	github.com/cilium/ebpf v0.8.0
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
)
