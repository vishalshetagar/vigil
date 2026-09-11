// SPDX-License-Identifier: GPL-2.0-only
// Kernel-only probe code. The userspace sensor never enforces a deny policy.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "include/events.h"

// Minimal CO-RE type descriptions. Offsets are relocated against target BTF.
typedef struct { int counter; } atomic_t;
struct signal_struct { atomic_t live; } __attribute__((preserve_access_index));
struct cred {
    struct { unsigned int val; } uid;
    struct { unsigned int val; } gid;
} __attribute__((preserve_access_index));
struct task_struct {
    int pid;
    int tgid;
    __u64 start_boottime;
    struct task_struct *group_leader;
    struct task_struct *real_parent;
    struct signal_struct *signal;
    const struct cred *cred;
    char comm[16];
} __attribute__((preserve_access_index));
struct linux_binprm { const char *filename; } __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vigil_stats);
} stats SEC(".maps");

struct pending_connect {
    __u64 start_ns;
    __u16 family;
    __u16 port;
    __u8 address[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct pending_connect);
} connects SEC(".maps");

static __always_inline struct vigil_stats *counters(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&stats, &zero);
}

static __always_inline __u64 birth(struct task_struct *task) {
    return BPF_CORE_READ(task, group_leader, start_boottime);
}

static __always_inline struct vigil_event *new_event(__u16 type, struct task_struct *task) {
    struct vigil_stats *s = counters();
    struct vigil_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        if (s) s->ring_lost++;
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->version = VIGIL_ABI;
    e->type = type;
    e->size = sizeof(*e);
    e->time_ns = bpf_ktime_get_ns();
    e->start_ns = birth(task);
    e->pid = BPF_CORE_READ(task, tgid);
    e->tid = BPF_CORE_READ(task, pid);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->parent_start_ns = birth(parent);
    e->uid = BPF_CORE_READ(task, cred, uid.val);
    e->gid = BPF_CORE_READ(task, cred, gid.val);
    // A fork hook runs in the parent; its cgroup need not be the child's.
    if (type != EVENT_FORK) e->cgroup = bpf_get_current_cgroup_id();
    e->cpu = bpf_get_smp_processor_id();
    if (BPF_CORE_READ_STR_INTO(&e->comm, task, comm) < 0) {
        e->flags |= FLAG_READ_ERROR;
        if (s) s->read_errors++;
    }
    if (s) e->sequence = ++s->emitted;
    return e;
}

SEC("raw_tracepoint/sched_process_fork")
int on_fork(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *child = (void *)ctx->args[1];
    // Threads share a process instance and do not create new process graph nodes.
    if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid)) return 0;
    struct vigil_event *e = new_event(EVENT_FORK, child);
    if (e) {
        // CLONE_PARENT can make real_parent differ from the task that created it.
        struct task_struct *creator = (void *)ctx->args[0];
        e->ppid = BPF_CORE_READ(creator, tgid);
        e->parent_start_ns = birth(creator);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int on_exec(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *task = (void *)ctx->args[0];
    struct linux_binprm *bprm = (void *)ctx->args[2];
    struct vigil_event *e = new_event(EVENT_EXEC, task);
    if (!e) return 0;
    e->old_pid = ctx->args[1];
    long n = bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));
    if (n < 0) {
        e->flags |= FLAG_READ_ERROR;
        struct vigil_stats *s = counters();
        if (s) s->read_errors++;
    } else if (n == sizeof(e->filename)) e->flags |= FLAG_TRUNCATED;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int on_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&connects, &id);
    struct task_struct *task = (void *)ctx->args[0];
    struct vigil_event *e = new_event(EVENT_EXIT, task);
    if (!e) return 0;
    // do_exit decrements signal->live before sched_process_exit.
    if (BPF_CORE_READ(task, signal, live.counter) == 0) e->flags |= FLAG_GROUP_DEAD;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct syscall_enter { __u64 common; __s64 nr; __u64 args[6]; };
struct syscall_exit { __u64 common; __s64 nr; __s64 ret; };

SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect_enter(struct syscall_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&connects, &id);
    void *address = (void *)ctx->args[1];
    __u32 len = ctx->args[2];
    __u16 family = 0;
    struct pending_connect p = {};
    if (len < 2 || bpf_probe_read_user(&family, 2, address)) goto read_error;
    if (family == 2) {
        struct { __u16 family; __u16 port; __u8 addr[4]; __u8 zero[8]; } a = {};
        if (len < sizeof(a) || bpf_probe_read_user(&a, sizeof(a), address)) goto read_error;
        p.port = __builtin_bswap16(a.port);
        __builtin_memcpy(p.address, a.addr, 4);
    } else if (family == 10) {
        struct { __u16 family; __u16 port; __u32 flow; __u8 addr[16]; __u32 scope; } a = {};
        if (len < sizeof(a) || bpf_probe_read_user(&a, sizeof(a), address)) goto read_error;
        p.port = __builtin_bswap16(a.port);
        __builtin_memcpy(p.address, a.addr, 16);
    } else return 0;
    p.family = family;
    p.start_ns = birth((void *)bpf_get_current_task());
    if (bpf_map_update_elem(&connects, &id, &p, BPF_ANY)) {
        struct vigil_stats *s = counters();
        if (s) s->map_errors++;
    }
    return 0;
read_error:
    {
        struct vigil_stats *s = counters();
        if (s) s->read_errors++;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int on_connect_exit(struct syscall_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct pending_connect *p = bpf_map_lookup_elem(&connects, &id);
    if (!p) return 0;
    struct task_struct *task = (void *)bpf_get_current_task();
    if (p->start_ns != birth(task)) goto done;
    struct vigil_event *e = new_event(EVENT_CONNECT, task);
    if (!e) goto done;
    e->family = p->family;
    e->port = p->port;
    e->result = ctx->ret;
    __builtin_memcpy(e->address, p->address, 16);
    bpf_ringbuf_submit(e, 0);
done:
    bpf_map_delete_elem(&connects, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
