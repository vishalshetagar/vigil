package probe

// Requires Linux, clang/llvm-strip and libbpf-dev. The generated object is embedded.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -tags linux,amd64 -type vigil_stats sensor ../../bpf/sensor.bpf.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu
