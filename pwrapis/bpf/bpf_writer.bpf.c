/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * Description: eBPF program for writer attribution (P2). Hooks ksys_write
 *              via a kprobe and emits, for each write syscall, the identity
 *              of the writing process (uid/pid/comm) plus the first bytes of
 *              the user buffer. Path filtering and drift-target correlation
 *              is done in user space (bpfwriter.c) to keep the BPF program
 *              minimal, portable and free of kernel-version-specific
 *              task_struct traversal.
 *
 *              Build:  clang -target bpf -O2 -g -nostdinc \
 *                        -I<bpf-headers> -c bpf_writer.bpf.c -o bpf_writer.bpf.o
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

/* BPF helper prototypes (subset we use). */
static void *(*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u32 (*bpf_get_current_uid_gid)(void) = (void *)15;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_probe_read_user)(void *dst, u32 size, const void *src) = (void *)112;
static long (*bpf_perf_event_output)(void *ctx, void *map, u64 flags, void *data, u64 size) = (void *)25;

#define BPF_F_CURRENT_CPU 0xffffffffULL

/* Minimal BPF map definition the verifier expects in the .maps section.
 * Declared as a struct so clang emits an ELF section ".maps" the loader could
 * optionally inspect; the loader here, however, creates its own perf event
 * array in user space and ignores any map section, so this declaration exists
 * only to keep the program self-describing. */
struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
};

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

#define WRITER_BUF_LEN 64
#define WRITER_COMM_LEN 16

/* Emitted to user space via the perf ring buffer. Keep layout stable and
 * matching struct WriterEvent in bpfwriter.c. tid lets user space correlate
 * the write with the API call executing on that thread; ktime carries the
 * write-entry timestamp (CLOCK_MONOTONIC) so audit lines show the real
 * write time rather than the collector drain time. */
struct WriterEvent {
    u32 uid;
    s32 pid;
    s32 tid;
    char comm[WRITER_COMM_LEN];
    s32 fd;
    u32 bufLen;
    char buf[WRITER_BUF_LEN];
    u64 ktime;
};

/* The kprobe context is a pointer to the interrupted frame's pt_regs. Which
 * register holds each syscall argument differs per architecture, so the
 * layout is selected at BUILD time with -D__TARGET_ARCH_x86 or
 * -D__TARGET_ARCH_arm64. The BPF bytecode itself is architecture neutral;
 * only these load offsets differ, hence one object file per arch is shipped
 * (bpf_writer_x86.bpf.o / bpf_writer_arm64.bpf.o) and the loader picks the
 * right one via uname(). */
#if defined(__TARGET_ARCH_arm64)
/* arm64: struct user_pt_regs { __u64 regs[31]; __u64 sp; __u64 pc;
 * __u64 pstate; }; syscall arguments arrive in x0..x2. */
struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};
#define PT_ARG1 regs[0]
#define PT_ARG2 regs[1]
#define PT_ARG3 regs[2]
#elif defined(__TARGET_ARCH_x86)
/* x86_64: the first three integer arguments sit in di/si/dx. */
struct pt_regs {
    u64 r15; u64 r14; u64 r13; u64 r12; u64 bp; u64 bx;
    u64 r11; u64 r10; u64 r9; u64 r8; u64 ax; u64 cx; u64 dx; u64 si; u64 di;
    u64 orig_ax;
    u64 ip; u64 cs; u64 flags; u64 sp; u64 ss;
};
#define PT_ARG1 di
#define PT_ARG2 si
#define PT_ARG3 dx
#else
#error "Define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 to select the pt_regs layout"
#endif

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

    /* The perf event array map handle is the symbol address; with perf_event_output
     * we pass &writer_events. */
    bpf_perf_event_output(ctx, &writer_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";

#endif
