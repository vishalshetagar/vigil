#ifndef VIGIL_EVENTS_H
#define VIGIL_EVENTS_H

#include <linux/types.h>

#define VIGIL_ABI 1
#define EVENT_FORK 1
#define EVENT_EXEC 2
#define EVENT_EXIT 3
#define EVENT_CONNECT 4
#define FLAG_TRUNCATED 1
#define FLAG_READ_ERROR 2
#define FLAG_GROUP_DEAD 4

struct vigil_event {
    __u16 version;
    __u16 type;
    __u32 size;
    __u64 time_ns;
    __u64 start_ns;
    __u64 parent_start_ns;
    __u64 cgroup;
    __u64 sequence;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 cpu;
    __u32 flags;
    __u32 old_pid;
    __s64 result;
    __u16 family;
    __u16 port;
    __u32 padding;
    __u8 address[16];
    char comm[16];
    char filename[256];
};

_Static_assert(sizeof(struct vigil_event) == 384, "Vigil ABI size changed");
_Static_assert(__builtin_offsetof(struct vigil_event, filename) == 128, "Vigil ABI offset changed");

struct vigil_stats {
    __u64 emitted;
    __u64 ring_lost;
    __u64 read_errors;
    __u64 map_errors;
};
#endif
