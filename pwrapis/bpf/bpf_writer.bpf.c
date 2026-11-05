/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * Description: eBPF program for writer attribution (P2). Hooks ksys_write via
 *              a kprobe and emits, for each write syscall, the identity of
 *              the writing process (uid/pid/comm) plus the first bytes of the
 *              user buffer. Legacy deployments resolved the path of each fd
 *              in user space via /proc/<pid>/fd/<fd> after the fact, which
 *              silently dropped every write whose fd was already closed again
 *              (echo > file, fopen/fwrite/fclose, shell redirections) - i.e.
 *              almost every short write worth auditing. This revision tracks
 *              fd -> path inside the kernel:
 *
 *                kp_open_enter  records the opened filename in a transient
 *                               tid-keyed map when it matches a watched path
 *                               prefix (empty marker otherwise);
 *                kr_open_exit   moves the name into the persistent
 *                               (pid,fd)-keyed fd_paths map, or invalidates
 *                               that key when an unwatched open reused the fd
 *                               number, so stale entries cannot survive fd
 *                               reuse;
 *                kp_dup3        replicates the entry on dup2/dup3, which is
 *                               how every shell builds redirections, and
 *                               invalidates the new fd when the old one was
 *                               not tracked;
 *                kp_cfr         fires on the copy_file_range syscall
 *                               wrapper: GNU cp (coreutils >= 8.25) moves
 *                               regular-file data with copy_file_range(2),
 *                               so a plain `cp src dst` never issues a
 *                               write(2) on the destination fd and the
 *                               write probe cannot see it. The wrapper's
 *                               argument is a struct pt_regs * holding the
 *                               raw syscall arguments, so the program reads
 *                               fd_out through it and emits the event with
 *                               the tracked path and a "(cfr)" value marker
 *                               (there is no user buffer to snapshot);
 *                kp_ksys_write  attaches the tracked path to the write event
 *                               at the moment of the write, so the path is
 *                               correct even when the fd closes before the
 *                               collector drains the ring. Untracked writes
 *                               are still emitted and fall back to the
 *                               legacy /proc lookup in user space, which
 *                               keeps long-lived fds opened before the
 *                               service started attributable.
 *
 *              Build:  clang -target bpf -O2 -g -nostdinc \
 *                        -D__TARGET_ARCH_<arch> -c bpf_writer.bpf.c \
 *                        -o bpf_writer_<arch>.bpf.o
 *
 *              The program is self-contained: it does NOT use CO-RE/BTF and
 *              does NOT require libbpf headers - only the few BPF helper
 *              prototypes it needs are declared inline below. A single build
 *              runs on any 5.x kernel with BPF enabled.
 * **************************************************************************** */
#ifndef __BPF_WRITER_BPF_C__
#define __BPF_WRITER_BPF_C__

/* The BPF target provides the following types and macros via its built-in
 * header <stdint.h>. clang's bpf target supports a small set of freestanding
 * headers; we avoid them to stay buildable without bpf_helpers.h. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef int            s32;
typedef long long      s64;

#ifndef NULL
#define NULL ((void *)0)
#endif

/* BPF helper prototypes (subset we use). */
static void *(*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u32 (*bpf_get_current_uid_gid)(void) = (void *)15;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_probe_read_user)(void *dst, u32 size, const void *src) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, u32 size, const void *src) = (void *)114;
static long (*bpf_perf_event_output)(void *ctx, void *map, u64 flags, void *data, u64 size) = (void *)25;
static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(const void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;

#define BPF_F_CURRENT_CPU 0xffffffffULL
#define BPF_ANY 0ULL

/* Map definitions below are self-describing only: the user-space loader
 * (bpfwriter.c) creates the real maps with these parameters, keyed by the
 * symbol name, and patches the relocations in each program accordingly. */

/* Perf event array shared by every probe: the write events. */
struct {
    u32 type;       /* BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4 */
    u32 key_size;
    u32 value_size;
    u32 max_entries;
} writer_events
__attribute__((section(".maps"), used)) = {
    .type = 4,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 128,
};

/* Transient: tid -> opened filename between kp_open_enter and kr_open_exit.
 * An empty value marks an unwatched (or unreadable) open so kr_open_exit can
 * pair with the enter event even when nothing was matched; this keeps the
 * enter/exit pairing consistent across fd reuse. */
struct {
    u32 type;       /* BPF_MAP_TYPE_HASH = 1 */
    u32 key_size;
    u32 value_size;
    u32 max_entries;
} open_paths
__attribute__((section(".maps"), used)) = {
    .type = 1,
    .key_size = sizeof(u32),
    .value_size = 64,
    .max_entries = 4096,
};

struct fd_path_value {
    u64 ktime;      /* open time, CLOCK_MONOTONIC ns */
    char path[64];
};

/* Persistent: (pid << 32 | fd) -> fd_path_value. Written on watched opens,
 * invalidated on unwatched opens (fd reuse) and untracked dup, replicated on
 * tracked dup, aged out by the collector via BPF_MAP_GET_NEXT_KEY. */
struct {
    u32 type;       /* BPF_MAP_TYPE_HASH = 1 */
    u32 key_size;
    u32 value_size;
    u32 max_entries;
} fd_paths
__attribute__((section(".maps"), used)) = {
    .type = 1,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct fd_path_value),
    .max_entries = 16384,
};

/* Watched path prefixes, populated from user space (index -> prefix). Unset
 * ARRAY slots read back as zeroed memory, hence the emptiness check. */
struct {
    u32 type;       /* BPF_MAP_TYPE_ARRAY = 2 */
    u32 key_size;
    u32 value_size;
    u32 max_entries;
} path_prefixes
__attribute__((section(".maps"), used)) = {
    .type = 2,
    .key_size = sizeof(u32),
    .value_size = 64,
    .max_entries = 16,
};

#define WRITER_BUF_LEN 64
#define WRITER_COMM_LEN 16
#define OPEN_PATH_LEN 64
#define PREFIX_SLOTS 16
/* fd numbers above 1M are never tracked (key packing sanity). */
#define FD_TRACK_MAX 1048576
/* A tracked path is attached only while fresh: long-lived fds opened long
 * ago are left to the /proc fallback, which resolves them reliably while
 * they stay open, and 2s covers every open-write-close-drain window. */
#define FD_PATH_TTL_NS 2000000000ULL

/* Emitted to user space via the perf ring buffer. Keep layout stable and
 * matching struct WriterEvent in bpfwriter.c. tid lets user space correlate
 * the write with the API call executing on that thread; ktime carries the
 * write-entry timestamp (CLOCK_MONOTONIC) so audit lines show the real
 * write time rather than the collector drain time. pathValid/path carry
 * the kernel-tracked path for this fd at write time; the event is emitted
 * short (through pathValid) when the fd is not tracked. */
struct WriterEvent {
    u32 uid;
    s32 pid;
    s32 tid;
    char comm[WRITER_COMM_LEN];
    s32 fd;
    u32 bufLen;
    char buf[WRITER_BUF_LEN];
    u64 ktime;
    u64 pathValid;
    char path[OPEN_PATH_LEN];
};

/* Size of the event without the path payload (offset of path). */
#define WRITER_EVENT_CORE 120

/* The kprobe context is a pointer to the interrupted frame's pt_regs. Which
 * register holds each syscall argument differs per architecture, so the
 * layout is selected at BUILD time with -D__TARGET_ARCH_x86 or
 * -D__TARGET_ARCH_arm64. The BPF bytecode itself is architecture neutral;
 * only these load offsets differ, hence one object file per arch is shipped
 * (bpf_writer_x86.bpf.o / bpf_writer_arm64.bpf.o) and the loader picks the
 * right one via uname(). The open probes may attach to either the internal
 * do_sys_openat2/do_sys_open helpers or to the syscall wrappers; the
 * filename argument sits in the same register position for all of them, so
 * one program serves every fallback. */
#if defined(__TARGET_ARCH_arm64)
/* arm64: struct user_pt_regs { __u64 regs[31]; __u64 sp; __u64 pc;
 * __u64 pstate; }; syscall arguments arrive in x0..x2, return in x0. */
struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};
#define PT_ARG1 regs[0]
#define PT_ARG2 regs[1]
#define PT_ARG3 regs[2]
#define PT_RET regs[0]
#elif defined(__TARGET_ARCH_x86)
/* x86_64: the first three integer arguments sit in di/si/dx, return in ax. */
struct pt_regs {
    u64 r15; u64 r14; u64 r13; u64 r12; u64 bp; u64 bx;
    u64 r11; u64 r10; u64 r9; u64 r8; u64 ax; u64 cx; u64 dx; u64 si; u64 di;
    u64 orig_ax;
    u64 ip; u64 cs; u64 flags; u64 sp; u64 ss;
};
#define PT_ARG1 di
#define PT_ARG2 si
#define PT_ARG3 dx
#define PT_RET ax
#else
#error "Define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 to select the pt_regs layout"
#endif

/* Offset of the destination fd (third syscall argument) inside the struct
 * pt_regs that the copy_file_range syscall wrapper receives as its only
 * argument: arm64 regs[2], x86_64 dx. */
#if defined(__TARGET_ARCH_arm64)
#define CFR_FDOUT_OFF 16
#else
#define CFR_FDOUT_OFF 96
#endif

/* True when path starts with the NUL-terminated prefix pfx. Bounded by the
 * 64-byte buffer size so the verifier can check the loop. */
static __attribute__((always_inline)) int match_prefix(const char *path, const char *pfx)
{
    int i;
    for (i = 0; i < OPEN_PATH_LEN; i++) {
        if (pfx[i] == '\0') {
            return 1; /* prefix exhausted: path starts with it */
        }
        if (path[i] != pfx[i]) {
            return 0;
        }
    }
    return 0; /* prefix ran past the buffer without a NUL: malformed */
}

/* do_sys_openat2(int dfd, const char *filename, struct open_how *how), and
 * the do_sys_open / syscall-wrapper variants all carry the filename pointer
 * in the second argument. Record it (or the empty marker) for the exit
 * probe to pair with. */
__attribute__((section("kprobe/do_sys_openat2"), used))
int kp_open_enter(struct pt_regs *ctx)
{
    const char *fname = (const char *)ctx->PT_ARG2;
    u64 pidTgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pidTgid;

    char path[OPEN_PATH_LEN] = {};
    long n = bpf_probe_read_user_str(path, sizeof(path), (const void *)fname);
    int matched = 0;
    if (n > 0 && path[0] != '\0') {
        u32 i;
        for (i = 0; i < PREFIX_SLOTS; i++) {
            u32 key = i;
            const char *pfx = bpf_map_lookup_elem(&path_prefixes, &key);
            if (pfx == NULL || pfx[0] == '\0') {
                continue; /* unset slot reads back zeroed */
            }
            if (match_prefix(path, pfx)) {
                matched = 1;
                break;
            }
        }
    }
    /* Unwatched or unreadable: keep the empty marker so the exit probe
     * still finds (and consumes) its entry and can invalidate the fd. */
    if (!matched) {
        path[0] = '\0';
    }
    bpf_map_update_elem(&open_paths, &tid, path, BPF_ANY);
    return 0;
}

__attribute__((section("kretprobe/do_sys_openat2"), used))
int kr_open_exit(struct pt_regs *ctx)
{
    long fd = (long)ctx->PT_RET;
    u64 pidTgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pidTgid;

    /* Map values are 8-byte aligned; copy through u64 views so clang emits
     * aligned word moves instead of expanding the copy byte by byte. */
    u64 *path = bpf_map_lookup_elem(&open_paths, &tid);
    if (path == NULL) {
        return 0; /* enter probe missed (e.g. map full): nothing to pair */
    }
    if (fd >= 0 && fd < FD_TRACK_MAX) {
        u64 key = (pidTgid << 32) | (u32)fd;
        if (((const char *)path)[0] != '\0') {
            struct fd_path_value val = {};
            __builtin_memcpy((u64 *)val.path, path, sizeof(val.path));
            val.ktime = bpf_ktime_get_ns();
            bpf_map_update_elem(&fd_paths, &key, &val, BPF_ANY);
        } else {
            /* The fd number now belongs to an unwatched file: drop any
             * stale entry from an earlier watched open, otherwise a later
             * write to this fd would inherit the old path. */
            bpf_map_delete_elem(&fd_paths, &key);
        }
    }
    bpf_map_delete_elem(&open_paths, &tid);
    return 0;
}

/* dup2/dup3: the new fd ends up referring to the same file as the old one,
 * so replicate the tracking entry; when the old fd was not tracked, the
 * new fd must not keep an entry of its own. dup2(f, f) rewrites the same
 * key with itself, which is harmless. */
__attribute__((section("kprobe/ksys_dup3"), used))
int kp_dup3(struct pt_regs *ctx)
{
    u64 pidTgid = bpf_get_current_pid_tgid();
    s32 oldfd = (s32)ctx->PT_ARG1;
    s32 newfd = (s32)ctx->PT_ARG2;
    if (oldfd < 0 || newfd < 0 || oldfd >= FD_TRACK_MAX || newfd >= FD_TRACK_MAX) {
        return 0;
    }
    u64 oldKey = (pidTgid << 32) | (u32)oldfd;
    u64 newKey = (pidTgid << 32) | (u32)newfd;
    struct fd_path_value *ov = bpf_map_lookup_elem(&fd_paths, &oldKey);
    if (ov != NULL) {
        struct fd_path_value nv = {};
        __builtin_memcpy(&nv, ov, sizeof(nv));
        bpf_map_update_elem(&fd_paths, &newKey, &nv, BPF_ANY);
    } else {
        bpf_map_delete_elem(&fd_paths, &newKey);
    }
    return 0;
}

/* copy_file_range: data moves kernel-side from fd_in to fd_out - no write(2)
 * reaches the destination fd, so kp_ksys_write never fires for a plain
 * `cp src dst` (GNU coreutils >= 8.25 uses copy_file_range for regular
 * files). The section name is a classification label only: the real attach
 * symbol is the arch syscall wrapper, resolved in user space. The wrapper's
 * sole argument is a struct pt_regs * holding the raw syscall arguments, so
 * fd_out is read through it at offset CFR_FDOUT_OFF. There is no user buffer
 * to snapshot, so the event carries a "(cfr)" marker as its value; the path
 * comes from the same fd-tracking map the write probe uses. */
__attribute__((section("kprobe/copy_file_range"), used))
int kp_cfr(struct pt_regs *ctx)
{
    const char *sysRegs = (const char *)(void *)ctx->PT_ARG1;
    u64 fdOut = 0;
    if (bpf_probe_read_kernel(&fdOut, sizeof(fdOut), sysRegs + CFR_FDOUT_OFF) != 0) {
        return 0;
    }
    int fd = (s32)fdOut;
    if (fd < 0 || fd >= FD_TRACK_MAX) {
        return 0;
    }

    struct WriterEvent ev = {};
    u64 pidTgid = bpf_get_current_pid_tgid();
    ev.pid = (s32)(pidTgid >> 32);
    ev.tid = (s32)(u32)pidTgid;
    ev.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.fd = fd;
    /* "(cfr)" - no user buffer exists in a copy_file_range call. Built via
     * immediate stores: a string literal would land in .rodata, which this
     * loader does not relocate. */
    ev.buf[0] = '(';
    ev.buf[1] = 'c';
    ev.buf[2] = 'f';
    ev.buf[3] = 'r';
    ev.buf[4] = ')';
    ev.bufLen = 5;
    ev.ktime = bpf_ktime_get_ns();

    u64 key = (pidTgid << 32) | (u32)fd;
    struct fd_path_value *tv = bpf_map_lookup_elem(&fd_paths, &key);
    if (tv != NULL && ev.ktime >= tv->ktime &&
        ev.ktime - tv->ktime <= FD_PATH_TTL_NS) {
        ev.pathValid = 1;
        __builtin_memcpy((u64 *)ev.path, (const u64 *)tv->path,
            sizeof(ev.path));
    }

    bpf_perf_event_output(ctx, &writer_events, BPF_F_CURRENT_CPU, &ev,
        ev.pathValid ? (u64)sizeof(ev) : (u64)WRITER_EVENT_CORE);
    return 0;
}

__attribute__((section("kprobe/ksys_write"), used))
int kp_ksys_write(struct pt_regs *ctx)
{
    /* ksys_write(int fd, const char *buf, size_t count) */
    int fd = (int)ctx->PT_ARG1;
    const char *buf = (const char *)ctx->PT_ARG2;
    u64 count = ctx->PT_ARG3;

    if (count == 0) {
        return 0;
    }

    struct WriterEvent ev = {};
    /* bpf_get_current_pid_tgid() = (tgid << 32) | tid; the process id lets
     * /proc/<pid>/fd/<fd> resolve in user space, the thread id correlates
     * the write with the API call executing on this thread. */
    u64 pidTgid = bpf_get_current_pid_tgid();
    ev.pid = (s32)(pidTgid >> 32);
    ev.tid = (s32)(u32)pidTgid;
    ev.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.fd = fd;
    ev.bufLen = WRITER_BUF_LEN;
    if (count < WRITER_BUF_LEN) {
        ev.bufLen = (u32)count;
    }
    bpf_probe_read_user(&ev.buf, ev.bufLen, (const void *)buf);
    ev.ktime = bpf_ktime_get_ns();

    /* Attach the tracked path for this fd if it is fresh; the write may
     * well be the last thing that happens before the fd closes, and the
     * user-space /proc lookup would then find nothing at drain time. */
    if (fd >= 0 && fd < FD_TRACK_MAX) {
        u64 key = (pidTgid << 32) | (u32)fd;
        struct fd_path_value *tv = bpf_map_lookup_elem(&fd_paths, &key);
        if (tv != NULL && ev.ktime >= tv->ktime &&
            ev.ktime - tv->ktime <= FD_PATH_TTL_NS) {
            ev.pathValid = 1;
            __builtin_memcpy((u64 *)ev.path, (const u64 *)tv->path,
                sizeof(ev.path));
        }
    }

    /* The perf event array map handle is the symbol address; with perf_event_output
     * we pass &writer_events. Emit the short form when no path is attached. */
    bpf_perf_event_output(ctx, &writer_events, BPF_F_CURRENT_CPU, &ev,
        ev.pathValid ? (u64)sizeof(ev) : (u64)WRITER_EVENT_CORE);
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";

#endif
