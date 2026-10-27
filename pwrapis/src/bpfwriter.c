/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * Description: loader/collector implementation for the writer-attribution
 *              eBPF programs. Uses the raw bpf() syscall and a hand-rolled
 *              ELF parser for the BPF object, so no libbpf dependency is
 *              required. Every kprobe/kretprobe section of the object is
 *              loaded as its own program; maps are created by their .maps
 *              symbol name. Kernel-side fd -> path tracking (open enter/exit
 *              pair plus the dup probe) attaches the real path of the fd to
 *              each write event at write time, so short-lived fds stay
 *              attributable; fds the probes never saw still fall back to
 *              the user-space /proc/<pid>/fd/<fd> lookup.
 * **************************************************************************** */
#include "bpfwriter.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "audit.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "pwrerr.h"
#include "utils.h"

/* Must match struct WriterEvent in bpf_writer.bpf.c byte for byte (natural
 * alignment). pathValid/path carry the kernel-tracked path of the written fd
 * captured at write time, so short-lived fds (open/write/close) stay
 * attributable even after the fd is gone; events without a tracked path are
 * emitted short (through pathValid) and fall back to the /proc lookup. */
#define WRITER_BUF_LEN 64
#define WRITER_COMM_LEN 16
#define WRITER_PATH_LEN 64
struct WriterEvent {
    unsigned int uid;
    int pid;
    int tid;
    char comm[WRITER_COMM_LEN];
    int fd;
    unsigned int bufLen;
    char buf[WRITER_BUF_LEN];
    uint64_t ktime;      /* bpf_ktime_get_ns() at write entry (CLOCK_MONOTONIC) */
    uint64_t pathValid;  /* 1 when path[] below holds the tracked path */
    char path[WRITER_PATH_LEN];
};
/* Offset of path in struct WriterEvent: the size of the short event form. */
#define WRITER_EVENT_CORE 120

/* Upstream helper symbols we may attach the open probes to, tried in order
 * (5.10 keeps do_sys_openat2/do_sys_open static, so they are only probeable
 * when the kernel was built with CONFIG_KALLSYMS_ALL; the syscall wrappers
 * are always present). The filename argument sits in the same register for
 * every entry of the chain, so one BPF program serves them all. */
#define OPEN_SYM_1 "do_sys_openat2"
#define OPEN_SYM_2 "do_sys_open"
/* dup2/dup3 chain: ksys_dup3 is static on 5.10; the wrappers always exist
 * (arm64 has no dup2 syscall - libc dup2() enters through dup3 there). */
#define DUP_SYM_1 "ksys_dup3"

/* tracefs kprobe_events instance names, one per probe. */
#define KP_NAME_WRITE "pwraudit_write"
#define KP_NAME_OPENENT "pwraudit_openent"
#define KP_NAME_OPENRET "pwraudit_openret"
#define KP_NAME_DUP3 "pwraudit_dup3"
#define KP_NAME_SYMTEST "pwraudit_symtest"

/* Number of BPF programs/maps the loader knows how to handle. */
#define BPF_MAX_PROGS 4
#define BPF_MAX_MAPS 4
/* Watched path prefixes pushed into the path_prefixes ARRAY map. */
#define BPF_PREFIX_SLOTS 8
/* fd_paths entries older than this are swept so the hash map cannot fill
 * up over weeks of distinct (pid, fd) pairs. Long-lived fds do not need
 * their entries: they resolve live via /proc while they stay open. */
#define FD_SWEEP_AGE_MS 30000

/* One loaded BPF program: which section it came from, which kernel symbol
 * the tracefs probe was registered on, and the cpu0 tracepoint carrier fd
 * that carries it. */
struct BpfProgCtx {
    char secName[48];
    char ksym[48];
    char kpName[32];
    int isRet; /* 1 = kretprobe (r:) */
    int secIdx;      /* ELF section index of the program */
    int registered;  /* 1 once the kprobe_events entry exists */
    int progFd;
    int tpFd;
    unsigned int tpId;
};
#define PERF_PAGE_COUNT 64
#define PERF_WATERMARK 1
#define MAX_WATCH_PATHS 64
/* Upper bound of monitored CPUs. The perf-event-array map is indexed by CPU
 * id, so its max_entries must be >= the highest monitored CPU index; both
 * derive from the online CPU count clamped here. */
#define MAX_CPUS 1024

/* Loaded programs (kprobe/ksys_write, open enter/exit pair, dup). */
static struct BpfProgCtx g_bpfProgs[BPF_MAX_PROGS];
static int g_bpfProgCnt = 0;
static int g_bpfMapFd = -1; /* the shared writer_events perf-event array */
/* Map fds by symbol name (writer_events/open_paths/fd_paths/path_prefixes). */
static int g_bpfMapFds[BPF_MAX_MAPS];
static char g_bpfMapNames[BPF_MAX_MAPS][24];
static int g_bpfMapCnt = 0;
/* 1 when the open/dup probes are attached (kernel-side fd tracking). */
static int g_fdTracking = 0;
/* One tracepoint perf fd (cpu0) carries each program; one BPF_OUTPUT ring
 * fd per online CPU is registered in the perf-event-array map. */
static int g_perfFd[MAX_CPUS];
static void *g_perfBase[MAX_CPUS];
static size_t g_perfMmapSize = 0;
static int g_perfCnt = 0;
static ThreadInfo g_writerThread;
static pthread_mutex_t g_writerLock = PTHREAD_MUTEX_INITIALIZER;
static int g_writerEnabled = 0;
static char g_watchPaths[MAX_WATCH_PATHS][MAX_FULL_NAME];
static int g_watchPathCount = 0;
/* Collector-thread statistics for field diagnosis; only the collector thread
 * touches them. Logged periodically so a broken event chain pinpoints itself:
 * records=0 -> kprobe/perf delivers nothing; samples=0 -> ring overflow
 * (lost) or bad records; resolveFail high -> /proc lookup failing; watched=0
 * with samples high -> path filter mismatch; watched>0 but no audit lines ->
 * audit write path broken. */
static uint64_t g_statRecords;
static uint64_t g_statLost;
static uint64_t g_statSamples;
static uint64_t g_statBadRaw;
static uint64_t g_statResolveFail;
static uint64_t g_statTracked;
static uint64_t g_statWatched;

static void CleanupPerf(void);
static void CloseLoadedObjects(void);
static int FindMapFd(const char *name);

/* ---- minimal ELF helpers: find the first SHT_PROGBITS in section 1..n ---- */

struct ElfHdr {
    unsigned char ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

struct Shdr {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
};

struct Sym {
    uint32_t name;
    uint8_t  info;
    uint8_t  other;
    uint16_t shndx;
    uint64_t value;
    uint64_t size;
};

struct Rela {
    uint64_t offset;
    uint64_t info;
};

/* BPF instruction (8 bytes). For ld_imm64 the map fd goes into the low 32
 * bits of the first half and src_reg must be BPF_PSEUDO_MAP_FD (1). */
struct BpfInsn {
    uint8_t  code;
    uint8_t  regs;
    int16_t  off;
    int32_t  imm;
};

#define BPF_PSEUDO_MAP_FD 1
#define BPF_LD_IMM64 0x18

/* ELF section type for SHT_RELA (relocations with addends). */
#define SHT_RELA 4

/* The verifier log is multi-line and, for loop-heavy programs at
 * log_level=2, can reach megabytes. Flatten its TAIL onto a single log
 * line: the kernel writes the final verdict (processed insns, the
 * failing instruction) at the END, so keeping the head would hide
 * exactly the part that explains a failure. */
static void FlattenVerifierLog(const char *log, char *out, size_t outSize)
{
    size_t len = (log != NULL) ? strlen(log) : 0;
    size_t start = 0;
    if (len > outSize * 2) {
        size_t winStart = len - outSize * 2;
        start = winStart;
        while (start < len && log[start] != '\n') {
            start++; /* skip into the middle of a line */
        }
        if (start >= len) {
            /* No newline in the whole window (defensive: verifier lines
             * always end with '\n', but never drop the diagnostics). */
            start = winStart;
        } else {
            start++;
        }
    }
    size_t o = 0;
    for (size_t i = start; i < len && o + 1 < outSize; i++) {
        out[o++] = (log[i] == '\n') ? '|' : log[i];
    }
    out[o] = '\0';
}

/* Upper bound of the verifier trace buffer for failure diagnostics. */
#define VERIFIER_LOG_MAX (1024U * 1024U)

/* On PROG_LOAD failure, try a minimal 2-insn kprobe program (r0=0; exit).
 * If even this fails, the kernel/LSM refuses BPF program loads in general
 * (environment problem); if it succeeds, the problem is in the writer
 * program's own instructions. Keeps field diagnosis to one log look. */
static void RunLoadProbe(void)
{
    struct BpfInsn insns[2];
    (void)memset(insns, 0, sizeof(insns));
    insns[0].code = 0xb7; /* BPF_ALU64 | BPF_MOV | BPF_K : r0 = 0 */
    insns[1].code = 0x95; /* BPF_JMP | BPF_EXIT */
    char logBuf[65536] = {0};
    union bpf_attr attr;
    bzero(&attr, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insns = (uint64_t)insns;
    attr.insn_cnt = 2;
    attr.license = (uint64_t)"GPL";
    attr.log_buf = (uint64_t)logBuf;
    attr.log_size = sizeof(logBuf);
    attr.log_level = 1;
    int fd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        Logger(ERROR, MD_NM_LOG, "LoadProbe: minimal kprobe program also failed: %d (%s). verifier: %.600s "
            "-> kernel/LSM refuses BPF program loads in general (environment, not our program).",
            errno, strerror(errno), logBuf);
        return;
    }
    close(fd);
    Logger(ERROR, MD_NM_LOG, "LoadProbe: minimal kprobe program loaded OK "
        "-> environment allows BPF loads; the failure is in the writer program itself.");
}

/* Create one BPF map by its .maps symbol name, with the parameters the
 * kernel-side fd tracking expects (see bpf_writer.bpf.c). The loader owns
 * the map layout so object file and user space cannot silently drift. */
static int CreateNamedMap(const char *name, int *outFd)
{
    union bpf_attr mapAttr;
    bzero(&mapAttr, sizeof(mapAttr));
    if (strcmp(name, "writer_events") == 0) {
        mapAttr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
        mapAttr.key_size = sizeof(int);
        mapAttr.value_size = sizeof(int);
        /* The map is indexed by CPU id (BPF_F_CURRENT_CPU), so max_entries
         * must cover every CPU we may attach a perf event to. */
        long nCpu = sysconf(_SC_NPROCESSORS_ONLN);
        mapAttr.max_entries =
            (uint32_t)(((nCpu > MAX_CPUS) || (nCpu <= 0)) ? MAX_CPUS : nCpu);
    } else if (strcmp(name, "open_paths") == 0) {
        mapAttr.map_type = BPF_MAP_TYPE_HASH;
        mapAttr.key_size = sizeof(uint32_t);          /* tid */
        mapAttr.value_size = WRITER_PATH_LEN;          /* filename or "" marker */
        mapAttr.max_entries = 4096;
    } else if (strcmp(name, "fd_paths") == 0) {
        mapAttr.map_type = BPF_MAP_TYPE_HASH;
        mapAttr.key_size = sizeof(uint64_t);           /* pid << 32 | fd */
        mapAttr.value_size = sizeof(uint64_t) + WRITER_PATH_LEN; /* ktime + path */
        mapAttr.max_entries = 16384;
    } else if (strcmp(name, "path_prefixes") == 0) {
        mapAttr.map_type = BPF_MAP_TYPE_ARRAY;
        mapAttr.key_size = sizeof(uint32_t);           /* slot index */
        mapAttr.value_size = WRITER_PATH_LEN;
        mapAttr.max_entries = BPF_PREFIX_SLOTS;
    } else {
        return PWR_ERR_COMMON;
    }
    int fd = (int)syscall(__NR_bpf, BPF_MAP_CREATE, &mapAttr, sizeof(mapAttr));
    if (fd < 0) {
        Logger(ERROR, MD_NM_LOG, "BPF_MAP_CREATE(%s) failed: %d (%s)",
            name, errno, strerror(errno));
        return PWR_ERR_SYS_EXCEPTION;
    }
    *outFd = fd;
    return PWR_SUCCESS;
}

static int FindMapFd(const char *name)
{
    for (int i = 0; i < g_bpfMapCnt; i++) {
        if (strcmp(g_bpfMapNames[i], name) == 0) {
            return g_bpfMapFds[i];
        }
    }
    return -1;
}

/* Apply the relocations of one program section: every ld_imm64 that
 * references a symbol defined in the .maps section is patched with the fd
 * of the map created under that symbol name. */
static int PatchMapRelocs(const void *obj, size_t objSize, const struct ElfHdr *eh,
    const struct Shdr *shdrs, const char *strtab, const struct Shdr *progSh,
    struct BpfInsn *insns, size_t insnCnt)
{
    for (int i = 0; i < eh->shnum; i++) {
        if (shdrs[i].type != SHT_RELA && shdrs[i].type != 9 /* SHT_REL */) {
            continue;
        }
        const char *rn = strtab + shdrs[i].name;
        /* Match ".rel" + progsecname or ".rela" + progsecname. */
        const char *want = strtab + progSh->name;
        const char *pfx = (shdrs[i].type == SHT_RELA) ? ".rela" : ".rel";
        size_t pfxLen = strlen(pfx);
        if (strncmp(rn, pfx, pfxLen) != 0 || strcmp(rn + pfxLen, want) != 0) {
            continue;
        }
        if (shdrs[i].link >= eh->shnum) {
            continue;
        }
        const struct Shdr *symSh = &shdrs[shdrs[i].link];
        if (symSh->offset + symSh->size > objSize || symSh->entsize == 0) {
            continue;
        }
        const struct Sym *syms = (const struct Sym *)((const uint8_t *)obj + symSh->offset);
        size_t symCnt = (size_t)(symSh->size / symSh->entsize);
        /* SHT_REL entries are 16 bytes {offset, info}; SHT_RELA entries are
         * 24 bytes {offset, info, addend}. Both share the first two fields,
         * so iterate with the correct stride and read offset+info per entry. */
        size_t entSize = (shdrs[i].type == SHT_RELA) ? 24 : sizeof(struct Rela);
        const uint8_t *relBase = (const uint8_t *)obj + shdrs[i].offset;
        size_t relaCnt = (size_t)(shdrs[i].size / entSize);
        for (size_t r = 0; r < relaCnt; r++) {
            const struct Rela *rel = (const struct Rela *)(relBase + r * entSize);
            uint32_t symIdx = (uint32_t)(rel->info >> 32);
            if (symIdx >= symCnt) {
                continue;
            }
            /* Only patch symbols that live in a .maps section. */
            uint16_t symShndx = syms[symIdx].shndx;
            if (symShndx == 0 || symShndx >= eh->shnum) {
                continue;
            }
            const char *symSecName = strtab + shdrs[symShndx].name;
            if (strcmp(symSecName, ".maps") != 0) {
                continue;
            }
            const char *symName = strtab + syms[symIdx].name;
            int mfd = FindMapFd(symName);
            if (mfd < 0) {
                Logger(WARNING, MD_NM_LOG, "No map created for symbol %s; relocation skipped.",
                    symName);
                continue;
            }
            size_t insnIdx = (size_t)(rel->offset / sizeof(struct BpfInsn));
            if (insnIdx + 1 >= insnCnt) {
                continue;
            }
            /* ld_imm64 spans two 8-byte insn slots. The regs byte packs
             * dst_reg (low nibble) and src_reg (high nibble): keep the
             * destination register chosen by the compiler and set only
             * src_reg = BPF_PSEUDO_MAP_FD. Writing the constant into the
             * whole byte clobbered dst_reg and left src_reg = 0, so the
             * kernel never recognised the map reference and the verifier
             * rejected the program with EACCES. */
            uint8_t dstReg = (uint8_t)(insns[insnIdx].regs & 0x0f);
            insns[insnIdx].code = BPF_LD_IMM64;
            insns[insnIdx].regs = (uint8_t)((BPF_PSEUDO_MAP_FD << 4) | dstReg);
            insns[insnIdx].imm = mfd;
            insns[insnIdx + 1].imm = 0;
        }
        break; /* only the one rela section matching progSh matters */
    }
    return PWR_SUCCESS;
}

/* Copy one program section out of the object, patch its map relocations and
 * load it as a kprobe program. */
static int LoadOneSection(const void *obj, size_t objSize, const struct ElfHdr *eh,
    const struct Shdr *shdrs, const char *strtab, struct BpfProgCtx *pc)
{
    const struct Shdr *progSh = &shdrs[pc->secIdx];
    if (progSh->offset + progSh->size > objSize) {
        return PWR_ERR_COMMON;
    }

    /* Copy instructions into a writable buffer (we may patch them). */
    size_t insnSize = (size_t)progSh->size;
    size_t insnCnt = insnSize / sizeof(struct BpfInsn);
    struct BpfInsn *insns = malloc(insnSize);
    if (insns == NULL) {
        return PWR_ERR_COMMON;
    }
    memcpy(insns, (const uint8_t *)obj + progSh->offset, insnSize);

    if (PatchMapRelocs(obj, objSize, eh, shdrs, strtab, progSh, insns, insnCnt) !=
        PWR_SUCCESS) {
        free(insns);
        return PWR_ERR_COMMON;
    }

    /* Load the program with the (possibly patched) instructions.
     *
     * Attempt 1 deliberately passes NO verifier log buffer (log fields all
     * zero). With a log attached and log_level >= 1, the 5.10 verifier
     * dumps a register/stack precision backtrace for every stack slot
     * access; loop-heavy programs (e.g. the 8-prefix-slot scan) generate
     * traces far beyond 64KB, and once the buffer fills the kernel aborts
     * the load with ENOSPC -- which masks the real verdict entirely.
     * libbpf does the same: try silently first, ask for a log only after
     * a failure. */
    union bpf_attr attr;
    bzero(&attr, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insns = (uint64_t)insns;
    attr.insn_cnt = (uint32_t)insnCnt;
    attr.license = (uint64_t)"GPL";
    /* attr.log_buf/log_size/log_level stay zero: silent load. */

    int progFd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (progFd >= 0) {
        free(insns);
        pc->progFd = progFd;
        return PWR_SUCCESS;
    }
    int savedErrno = errno;
    /* Retry once with a large log buffer to capture the real verdict
     * (the verdict sits at the END of the trace, hence FlattenVerifierLog
     * keeps the tail). 1MB covers the most verbose loop-heavy programs. */
    char *logBuf = malloc(VERIFIER_LOG_MAX);
    if (logBuf == NULL) {
        Logger(ERROR, MD_NM_LOG, "BPF_PROG_LOAD(%s) failed: %d (%s). insnCnt:%u "
            "log-enabled retry skipped: log buffer alloc failed: %d (%s).",
            pc->secName, savedErrno, strerror(savedErrno), (unsigned)insnCnt,
            errno, strerror(errno));
    } else {
        logBuf[0] = '\0';
        attr.log_buf = (uint64_t)logBuf;
        attr.log_size = VERIFIER_LOG_MAX;
        attr.log_level = 2;
        int fd2 = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
        if (fd2 >= 0) {
            Logger(WARNING, MD_NM_LOG, "BPF_PROG_LOAD(%s) failed: %d (%s) but succeeded on "
                "the log-enabled retry (transient failure). insnCnt:%u",
                pc->secName, savedErrno, strerror(savedErrno), (unsigned)insnCnt);
            free(logBuf);
            free(insns);
            pc->progFd = fd2;
            return PWR_SUCCESS;
        }
        char flat[2400];
        FlattenVerifierLog(logBuf, flat, sizeof(flat));
        Logger(ERROR, MD_NM_LOG, "BPF_PROG_LOAD(%s) failed: %d (%s). insnCnt:%u verifier tail: %s",
            pc->secName, errno, strerror(errno), (unsigned)insnCnt, flat);
        if (errno == ENOSPC) {
            Logger(WARNING, MD_NM_LOG, "The 1MB verifier log itself overflowed on retry; "
                "the tail above ends where the buffer filled, the final verdict may be absent.");
        }
        free(logBuf);
    }
    RunLoadProbe();
    free(insns);
    return PWR_ERR_SYS_EXCEPTION;
}

/* Parse the BPF ELF object, create the maps its programs reference, apply
 * relocations (patch map fds into ld_imm64 instructions) and load every
 * kprobe/kretprobe section as its own program. On success g_bpfProgs holds
 * the loaded programs. Returns PWR_SUCCESS or an error. */
static int ParseAndLoadBpf(void *obj, size_t objSize)
{
    const struct ElfHdr *eh = (const struct ElfHdr *)obj;
    if (objSize < sizeof(struct ElfHdr) || eh->ident[0] != 0x7f ||
        eh->ident[1] != 'E' || eh->ident[2] != 'L' || eh->ident[3] != 'F') {
        return PWR_ERR_COMMON;
    }
    if (eh->ident[4] != 2 || eh->ident[5] != 1) { /* 64-bit LE only */
        return PWR_ERR_COMMON;
    }
    if (eh->shoff == 0 || eh->shnum == 0 || eh->shentsize < sizeof(struct Shdr)) {
        return PWR_ERR_COMMON;
    }
    const struct Shdr *shdrs = (const struct Shdr *)((const uint8_t *)obj + eh->shoff);
    if (eh->shstrndx >= eh->shnum) {
        return PWR_ERR_COMMON;
    }
    const struct Shdr *strSh = &shdrs[eh->shstrndx];
    if (strSh->offset + strSh->size > objSize) {
        return PWR_ERR_COMMON;
    }
    const char *strtab = (const char *)obj + strSh->offset;

    /* 1. Collect the program sections: each kprobe/<sym> or kretprobe/<sym>
     *    section is one program probing kernel symbol <sym>. Attach may
     *    substitute alternative symbols (see AttachPerCpu) for helper
     *    functions that are static and unprobeable on some kernels. */
    g_bpfProgCnt = 0;
    for (int i = 0; i < eh->shnum && g_bpfProgCnt < BPF_MAX_PROGS; i++) {
        if (shdrs[i].type != 1 /* SHT_PROGBITS */ || shdrs[i].size == 0) {
            continue;
        }
        const char *name = strtab + shdrs[i].name;
        const char *sym = NULL;
        int isRet = 0;
        if (strncmp(name, "kretprobe/", 10) == 0) {
            sym = name + 10;
            isRet = 1;
        } else if (strncmp(name, "kprobe/", 7) == 0) {
            sym = name + 7;
        }
        if (sym == NULL || sym[0] == '\0') {
            continue;
        }
        struct BpfProgCtx *pc = &g_bpfProgs[g_bpfProgCnt];
        (void)memset(pc, 0, sizeof(*pc));
        (void)snprintf(pc->secName, sizeof(pc->secName), "%s", name);
        (void)snprintf(pc->ksym, sizeof(pc->ksym), "%s", sym);
        pc->isRet = isRet;
        pc->secIdx = i;
        pc->progFd = -1;
        pc->tpFd = -1;
        /* Stable tracefs instance names for the known programs. */
        if (isRet == 0 && strcmp(sym, "ksys_write") == 0) {
            (void)snprintf(pc->kpName, sizeof(pc->kpName), "%s", KP_NAME_WRITE);
        } else if (isRet == 0 && strcmp(sym, "do_sys_openat2") == 0) {
            (void)snprintf(pc->kpName, sizeof(pc->kpName), "%s", KP_NAME_OPENENT);
        } else if (isRet == 1 && strcmp(sym, "do_sys_openat2") == 0) {
            (void)snprintf(pc->kpName, sizeof(pc->kpName), "%s", KP_NAME_OPENRET);
        } else if (isRet == 0 && strcmp(sym, "ksys_dup3") == 0) {
            (void)snprintf(pc->kpName, sizeof(pc->kpName), "%s", KP_NAME_DUP3);
        } else {
            (void)snprintf(pc->kpName, sizeof(pc->kpName), "pwraudit_p%d", g_bpfProgCnt);
        }
        g_bpfProgCnt++;
    }
    if (g_bpfProgCnt == 0) {
        Logger(ERROR, MD_NM_LOG, "No BPF program section found.");
        return PWR_ERR_COMMON;
    }

    /* 2. Create the maps the programs reference, by .maps symbol name. */
    static const char *const mapNames[] = {
        "writer_events", "open_paths", "fd_paths", "path_prefixes",
    };
    g_bpfMapCnt = 0;
    for (size_t i = 0; i < sizeof(mapNames) / sizeof(mapNames[0]); i++) {
        int fd = -1;
        if (CreateNamedMap(mapNames[i], &fd) != PWR_SUCCESS) {
            CloseLoadedObjects();
            return PWR_ERR_SYS_EXCEPTION;
        }
        g_bpfMapFds[g_bpfMapCnt] = fd;
        (void)snprintf(g_bpfMapNames[g_bpfMapCnt], sizeof(g_bpfMapNames[0]), "%s",
            mapNames[i]);
        g_bpfMapCnt++;
    }
    g_bpfMapFd = FindMapFd("writer_events");

    /* 3. Load every program (relocations are patched per section). */
    for (int p = 0; p < g_bpfProgCnt; p++) {
        if (LoadOneSection(obj, objSize, eh, shdrs, strtab, &g_bpfProgs[p]) != PWR_SUCCESS) {
            CloseLoadedObjects();
            return PWR_ERR_SYS_EXCEPTION;
        }
    }
    Logger(INFO, MD_NM_LOG, "BPF writer object loaded: %d programs, %d maps, perfMapFd:%d",
        g_bpfProgCnt, g_bpfMapCnt, g_bpfMapFd);
    return PWR_SUCCESS;
}

/* Pick the BPF object file matching the running CPU architecture. The
 * pt_regs layout (and therefore the register-load offsets baked into the
 * bytecode) differs between x86_64 and arm64, so one object per arch ships
 * next to the service and the loader selects via uname(). A configured path
 * ending in ".o" is honored as an explicit override; a configured directory
 * (or the default) gets bpf_writer_<arch>.bpf.o appended. */
static void ResolveObjPath(char *out, size_t outSize)
{
    const char *cfgPath = GetBpfCfg()->objPath;
    const char *dir = (cfgPath[0] != '\0') ? cfgPath : BPF_OBJ_DEFAULT_PATH;
    size_t len = strlen(dir);
    if (len >= 3 && strcmp(dir + len - 3, ".o") == 0) {
        (void)snprintf(out, outSize, "%s", dir);
        return;
    }
    struct utsname uts;
    const char *arch = "x86";
    if (uname(&uts) == 0 &&
        (strcmp(uts.machine, "aarch64") == 0 || strcmp(uts.machine, "arm64") == 0 ||
         strncmp(uts.machine, "armv8", 5) == 0)) {
        arch = "arm64";
    }
    (void)snprintf(out, outSize, "%s/bpf_writer_%s.bpf.o", dir, arch);
}

static int LoadBpfObject(void)
{
    char objPath[MAX_FULL_NAME];
    ResolveObjPath(objPath, sizeof(objPath));
    FILE *fp = fopen(objPath, "rb");
    if (fp == NULL) {
        Logger(WARNING, MD_NM_LOG, "BPF object not found at %s, writer attribution disabled.", objPath);
        return PWR_ERR_FILE_OPEN_FAILED;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(fp);
        return PWR_ERR_COMMON;
    }
    void *obj = malloc((size_t)sz);
    if (obj == NULL) {
        fclose(fp);
        return PWR_ERR_COMMON;
    }
    if (fread(obj, 1, (size_t)sz, fp) != (size_t)sz) {
        free(obj);
        fclose(fp);
        return PWR_ERR_COMMON;
    }
    fclose(fp);

    int ret = ParseAndLoadBpf(obj, (size_t)sz);
    free(obj);
    return ret;
}

/* ---- tracefs (kprobe_events) helpers for the classic attach path ---- */

/* Locate the tracefs mount that holds kprobe_events (openEuler/OLK 5.10 mounts
 * tracefs at /sys/kernel/tracing; older setups use debugfs). */
static bool FindTracefsDir(char *out, size_t outSize)
{
    static const char *cands[] = {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"};
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        char probe[MAX_FULL_NAME];
        (void)snprintf(probe, sizeof(probe), "%s/kprobe_events", cands[i]);
        if (access(probe, W_OK) == 0) {
            (void)snprintf(out, outSize, "%s", cands[i]);
            return true;
        }
    }
    return false;
}

/* Append one command line to a tracefs control file (kprobe_events). */
static int WriteTraceCmd(const char *traceDir, const char *file, const char *cmd)
{
    char path[MAX_FULL_NAME];
    (void)snprintf(path, sizeof(path), "%s/%s", traceDir, file);
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        return PWR_ERR_FILE_OPEN_FAILED;
    }
    size_t len = strlen(cmd);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, cmd + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return PWR_ERR_COMMON;
        }
        off += (size_t)n;
    }
    close(fd);
    return PWR_SUCCESS;
}

/* Delete one of our kprobes from kprobe_events by name. Only succeeds after
 * every perf fd referencing the event is closed (otherwise the kernel
 * refuses with EBUSY); CleanupPerf therefore closes the fds first.
 * Best-effort: a failure here only leaves a harmless unused probe behind. */
static void RemoveKprobeByName(const char *kpName)
{
    char traceDir[MAX_FULL_NAME];
    char cmd[64];
    if (!FindTracefsDir(traceDir, sizeof(traceDir))) {
        return;
    }
    (void)snprintf(cmd, sizeof(cmd), "-:%s", kpName);
    if (WriteTraceCmd(traceDir, "kprobe_events", cmd) != PWR_SUCCESS) {
        Logger(WARNING, MD_NM_LOG, "Remove kprobe event %s failed: %d (%s)",
            kpName, errno, strerror(errno));
    }
}

/* Probe whether a kernel symbol can be registered in kprobe_events: register
 * a scratch probe on it, then remove it again. Helper functions like
 * do_sys_openat2/ksys_dup3 are static on 5.10 and only kprobe-able when the
 * kernel was built with CONFIG_KALLSYMS_ALL, so availability has to be
 * tested, not assumed. */
static bool SymbolProbeable(const char *traceDir, const char *sym)
{
    char cmd[128];
    (void)snprintf(cmd, sizeof(cmd), "-:%s", KP_NAME_SYMTEST);
    (void)WriteTraceCmd(traceDir, "kprobe_events", cmd); /* clear a stale one */
    (void)snprintf(cmd, sizeof(cmd), "p:%s %s", KP_NAME_SYMTEST, sym);
    if (WriteTraceCmd(traceDir, "kprobe_events", cmd) != PWR_SUCCESS) {
        return false;
    }
    (void)snprintf(cmd, sizeof(cmd), "-:%s", KP_NAME_SYMTEST);
    (void)WriteTraceCmd(traceDir, "kprobe_events", cmd);
    return true;
}

/* Prefix of the arch syscall wrapper symbols (__arm64_sys_ / __x64_sys_). */
static const char *SyscallWrapperPrefix(void)
{
    struct utsname uts;
    if (uname(&uts) == 0 &&
        (strcmp(uts.machine, "aarch64") == 0 || strcmp(uts.machine, "arm64") == 0 ||
         strncmp(uts.machine, "armv8", 5) == 0)) {
        return "__arm64_sys_";
    }
    return "__x64_sys_";
}

/* Pick the symbol for the open probes: prefer do_sys_openat2 (covers
 * open/openat/openat2), then do_sys_open, then the arch syscall wrapper
 * for openat. Enter and exit probes must hook the SAME symbol or their
 * events would pair across different calls. NULL when nothing is probeable. */
static const char *ResolveOpenSymbol(const char *traceDir)
{
    static char wrapName[32];
    const char *chain[3] = {OPEN_SYM_1, OPEN_SYM_2, NULL};
    (void)snprintf(wrapName, sizeof(wrapName), "%sopenat", SyscallWrapperPrefix());
    chain[2] = wrapName;
    for (int i = 0; i < 3; i++) {
        if (SymbolProbeable(traceDir, chain[i])) {
            return chain[i];
        }
    }
    return NULL;
}

/* Same for the dup probe: ksys_dup3, then the arch dup3 syscall wrapper
 * (arm64 has no dup2 syscall - libc dup2() enters via dup3 there), and the
 * dup2 wrapper on x86_64 where the syscall still exists. */
static const char *ResolveDupSymbol(const char *traceDir)
{
    static char wrapDup3[32];
    static char wrapDup2[32];
    const char *chain[3] = {DUP_SYM_1, NULL, NULL};
    int len = 1;
    (void)snprintf(wrapDup3, sizeof(wrapDup3), "%sdup3", SyscallWrapperPrefix());
    chain[len++] = wrapDup3;
    if (strcmp(SyscallWrapperPrefix(), "__x64_sys_") == 0) {
        (void)snprintf(wrapDup2, sizeof(wrapDup2), "%sdup2", SyscallWrapperPrefix());
        chain[len++] = wrapDup2;
    }
    for (int i = 0; i < len; i++) {
        if (SymbolProbeable(traceDir, chain[i])) {
            return chain[i];
        }
    }
    return NULL;
}

/* Undo one AttachOneProbe (carrier fd first, then the probe entry). */
static void DetachOneProbe(struct BpfProgCtx *pc)
{
    if (pc->tpFd >= 0) {
        (void)ioctl(pc->tpFd, PERF_EVENT_IOC_DISABLE, 0);
        close(pc->tpFd);
        pc->tpFd = -1;
    }
    if (pc->registered) {
        RemoveKprobeByName(pc->kpName);
        pc->registered = 0;
    }
}

/* Register one probe in kprobe_events and hang the loaded program on a
 * cpu0 tracepoint carrier for it (the model bcc/libbpf use on 5.x):
 *
 *   1. Register the probe via <tracefs>/kprobe_events, then read the
 *      auto-assigned tracepoint id from events/kprobes/<name>/id.
 *   2. Open ONE tracepoint perf event (cpu0) and attach the loaded program
 *      with PERF_EVENT_IOC_SET_BPF. Opening the event enables the underlying
 *      kprobe (TRACE_REG_PERF_REGISTER -> TP_FLAG_PROFILE + enable_kprobe),
 *      and SET_BPF installs the program into the kprobe event's shared
 *      prog_array, so the program runs on every CPU where the kprobe fires.
 *      No per-CPU kprobe fds are needed for the BPF output.
 *
 * The kprobe PMU is not viable: it does not exist in mainline 5.10
 * trace_kprobe.c (vendor backports open fine but never enable the probe
 * into the perf/BPF path), and its fds are rejected by
 * __bpf_perf_event_output (-EINVAL) because they are not
 * PERF_COUNT_SW_BPF_OUTPUT software events, so the ring stayed empty.
 *
 * Requires root / CAP_PERFMON plus CONFIG_KPROBE_EVENTS. On failure
 * everything registered here is undone again. */
static int AttachOneProbe(struct BpfProgCtx *pc, const char *traceDir, const char *sym)
{
    char cmd[128];
    /* Best-effort cleanup of a stale probe left by a crashed previous run;
     * an existing probe would make the registration below fail with EEXIST. */
    (void)snprintf(cmd, sizeof(cmd), "-:%s", pc->kpName);
    (void)WriteTraceCmd(traceDir, "kprobe_events", cmd);

    (void)snprintf(cmd, sizeof(cmd), "%c:%s %s", pc->isRet ? 'r' : 'p', pc->kpName, sym);
    if (WriteTraceCmd(traceDir, "kprobe_events", cmd) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_LOG, "Register probe '%s' failed: %d (%s). "
            "Need CONFIG_KPROBE_EVENTS and a kprobe-able %s.",
            cmd, errno, strerror(errno), sym);
        return PWR_ERR_SYS_EXCEPTION;
    }
    pc->registered = 1;

    char idPath[MAX_FULL_NAME + 64];
    (void)snprintf(idPath, sizeof(idPath), "%s/events/kprobes/%s/id",
        traceDir, pc->kpName);
    unsigned int tpId = 0;
    FILE *fp = fopen(idPath, "r");
    if (fp != NULL) {
        if (fscanf(fp, "%u", &tpId) != 1) {
            tpId = 0;
        }
        fclose(fp);
    }
    if (tpId == 0) {
        Logger(ERROR, MD_NM_LOG, "Cannot read tracepoint id from %s.", idPath);
        goto fail;
    }

    /* The prog carrier: one tracepoint perf event on cpu0. */
    struct perf_event_attr pea;
    bzero(&pea, sizeof(pea));
    pea.type = PERF_TYPE_TRACEPOINT;
    pea.size = sizeof(pea);
    pea.config = tpId;
    pea.sample_period = 1;                 /* record every hit */
    pea.sample_type = PERF_SAMPLE_RAW;
    pea.wakeup_events = PERF_WATERMARK;
    pea.disabled = 1;
    int tpFd = (int)syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
    if (tpFd < 0) {
        Logger(WARNING, MD_NM_LOG, "perf_event_open tracepoint %u cpu0 failed: %d (%s). "
            "Need root / CAP_PERFMON.", tpId, errno, strerror(errno));
        goto fail;
    }
    if (ioctl(tpFd, PERF_EVENT_IOC_SET_BPF, pc->progFd) < 0) {
        Logger(ERROR, MD_NM_LOG, "PERF_EVENT_IOC_SET_BPF failed: %d (%s)", errno, strerror(errno));
        close(tpFd);
        goto fail;
    }
    pc->tpFd = tpFd;
    pc->tpId = tpId;
    return PWR_SUCCESS;

fail:
    DetachOneProbe(pc);
    return PWR_ERR_SYS_EXCEPTION;
}

/* Attach the writer probes with the classic kprobe_events + tracepoint path:
 *   - pwraudit_write on ksys_write (mandatory): captures every write;
 *   - pwraudit_openent + pwraudit_openret on one shared open symbol:
 *     kernel-side fd -> path tracking, so short-lived fds stay attributable;
 *   - pwraudit_dup3 on dup2/dup3: keeps tracked paths correct across the
 *     dup dance every shell performs for redirections.
 * One BPF_OUTPUT ring per CPU is shared by all probes, which preserves
 * event order across programs. pid = -1 so writes from every process are
 * captured. On partial failure the caller degrades gracefully: the write
 * probe alone still audits long-lived fds, while everything short-lived
 * would be missed. */
static int AttachPerCpu(void)
{
    char traceDir[MAX_FULL_NAME];
    if (!FindTracefsDir(traceDir, sizeof(traceDir))) {
        Logger(ERROR, MD_NM_LOG, "tracefs kprobe_events not found (tracefs not mounted?). "
            "Writer attribution disabled.");
        return PWR_ERR_SYS_EXCEPTION;
    }

    int cpuCnt = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cpuCnt <= 0) {
        Logger(ERROR, MD_NM_LOG, "Invalid online cpu count %d.", cpuCnt);
        return PWR_ERR_SYS_EXCEPTION;
    }
    if (cpuCnt > MAX_CPUS) {
        Logger(WARNING, MD_NM_LOG, "Online cpus %d exceed %d; only the first %d are monitored.",
            cpuCnt, MAX_CPUS, MAX_CPUS);
        cpuCnt = MAX_CPUS;
    }

    /* One ring fd per monitored CPU plus the carrier fds; make sure the fd
     * limit allows it (e.g. 608 online CPUs vs a default soft limit of 1024). */
    struct rlimit nf;
    if (getrlimit(RLIMIT_NOFILE, &nf) == 0 && (int)nf.rlim_cur < cpuCnt + 64) {
        nf.rlim_cur = (nf.rlim_max == RLIM_INFINITY) ? 65536 : nf.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &nf) != 0 || (int)nf.rlim_cur < cpuCnt + 64) {
            Logger(WARNING, MD_NM_LOG, "RLIMIT_NOFILE raise to %ld insufficient for %d perf fds: %d (%s)",
                (long)nf.rlim_cur, cpuCnt, errno, strerror(errno));
        }
    }

    for (int i = 0; i < MAX_CPUS; i++) {
        g_perfFd[i] = -1;
        g_perfBase[i] = NULL;
    }

    /* Classify the loaded programs by the symbols their sections name. */
    struct BpfProgCtx *writeProg = NULL;
    struct BpfProgCtx *openEnt = NULL;
    struct BpfProgCtx *openRet = NULL;
    struct BpfProgCtx *dupProg = NULL;
    for (int i = 0; i < g_bpfProgCnt; i++) {
        struct BpfProgCtx *pc = &g_bpfProgs[i];
        if (pc->isRet == 0 && strcmp(pc->ksym, "ksys_write") == 0) {
            writeProg = pc;
        } else if (pc->isRet == 0 && strcmp(pc->ksym, "do_sys_openat2") == 0) {
            openEnt = pc;
        } else if (pc->isRet == 1 && strcmp(pc->ksym, "do_sys_openat2") == 0) {
            openRet = pc;
        } else if (pc->isRet == 0 && strcmp(pc->ksym, "ksys_dup3") == 0) {
            dupProg = pc;
        }
    }
    if (writeProg == NULL) {
        Logger(ERROR, MD_NM_LOG, "Writer program missing from BPF object.");
        return PWR_ERR_COMMON;
    }

    /* 1. Write probe: mandatory. */
    if (AttachOneProbe(writeProg, traceDir, writeProg->ksym) != PWR_SUCCESS) {
        goto fail;
    }

    /* 2. Open enter/exit pair on one shared symbol; without it every write
     *    through a short-lived fd loses its path. Degrade gracefully: a
     *    half-attached pair would leak open_paths entries, so undo the
     *    enter probe when the exit probe cannot attach. */
    g_fdTracking = 0;
    if (openEnt != NULL && openRet != NULL) {
        const char *openSym = ResolveOpenSymbol(traceDir);
        if (openSym == NULL) {
            Logger(WARNING, MD_NM_LOG, "No probeable open symbol; fd tracking disabled, "
                "short-lived-fd writes will be missed.");
        } else if (AttachOneProbe(openEnt, traceDir, openSym) != PWR_SUCCESS) {
            Logger(WARNING, MD_NM_LOG, "Open enter probe not attached; fd tracking disabled, "
                "short-lived-fd writes will be missed.");
        } else if (AttachOneProbe(openRet, traceDir, openSym) != PWR_SUCCESS) {
            DetachOneProbe(openEnt);
            Logger(WARNING, MD_NM_LOG, "Open exit probe not attached; fd tracking disabled, "
                "short-lived-fd writes will be missed.");
        } else {
            g_fdTracking = 1;
            Logger(INFO, MD_NM_LOG, "Open probes attached on %s.", openSym);
        }
    }

    /* 3. dup probe (shell redirections): pure refinement of fd tracking. */
    if (g_fdTracking && dupProg != NULL) {
        const char *dupSym = ResolveDupSymbol(traceDir);
        if (dupSym == NULL) {
            Logger(WARNING, MD_NM_LOG, "No probeable dup symbol; dup-based redirections "
                "not tracked.");
        } else if (AttachOneProbe(dupProg, traceDir, dupSym) != PWR_SUCCESS) {
            Logger(WARNING, MD_NM_LOG, "Dup probe not attached; dup-based redirections "
                "not tracked.");
        } else {
            Logger(INFO, MD_NM_LOG, "Dup probe attached on %s.", dupSym);
        }
    }

    /* 4. One BPF_OUTPUT software ring per CPU, registered in the shared
     *    perf-event-array map at the CPU index - exactly where every
     *    program's bpf_perf_event_output(BPF_F_CURRENT_CPU) looks the ring
     *    up. All probes share the same rings, which keeps event order. */
    struct perf_event_attr pea;
    bzero(&pea, sizeof(pea));
    pea.type = PERF_TYPE_SOFTWARE;
    pea.size = sizeof(pea);
    pea.config = PERF_COUNT_SW_BPF_OUTPUT;
    pea.sample_type = PERF_SAMPLE_RAW;
    pea.wakeup_events = PERF_WATERMARK;
    pea.disabled = 1;

    for (int i = 0; i < cpuCnt; i++) {
        /* perf_event_open(attr, pid=-1 all processes, cpu=i, group=-1, flags=0). */
        int fd = (int)syscall(__NR_perf_event_open, &pea, -1, i, -1, 0);
        if (fd < 0) {
            Logger(WARNING, MD_NM_LOG, "perf_event_open BPF_OUTPUT cpu%d failed: %d (%s). "
                "Writer attribution disabled.", i, errno, strerror(errno));
            goto fail;
        }
        /* Register the fd in the perf-event-array map at the CPU index. */
        uint64_t key = (uint64_t)i;
        union bpf_attr attr;
        bzero(&attr, sizeof(attr));
        attr.map_fd = g_bpfMapFd;
        attr.key = (uint64_t)(uintptr_t)&key;
        attr.value = (uint64_t)(uintptr_t)&fd;
        attr.flags = BPF_ANY;
        if ((int)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
            Logger(ERROR, MD_NM_LOG, "BPF_MAP_UPDATE_ELEM cpu%d failed: %d (%s)",
                i, errno, strerror(errno));
            close(fd);
            goto fail;
        }
        g_perfFd[i] = fd;
    }

    /* 5. Enable the rings first and the tracepoint carriers after, so no
     *    early probe hit can be dropped for lack of an enabled ring. */
    for (int i = 0; i < cpuCnt; i++) {
        if (ioctl(g_perfFd[i], PERF_EVENT_IOC_ENABLE, 0) < 0) {
            Logger(ERROR, MD_NM_LOG, "PERF_EVENT_IOC_ENABLE cpu%d failed: %d (%s)",
                i, errno, strerror(errno));
            goto fail;
        }
    }
    for (int i = 0; i < g_bpfProgCnt; i++) {
        if (g_bpfProgs[i].tpFd >= 0 &&
            ioctl(g_bpfProgs[i].tpFd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
            Logger(ERROR, MD_NM_LOG, "PERF_EVENT_IOC_ENABLE %s failed: %d (%s)",
                g_bpfProgs[i].kpName, errno, strerror(errno));
            goto fail;
        }
    }

    g_perfCnt = cpuCnt;
    Logger(INFO, MD_NM_LOG, "Writer probes attached: %d programs (fdTracking:%d), "
        "%d BPF_OUTPUT rings enabled.", g_bpfProgCnt, g_fdTracking, cpuCnt);
    return PWR_SUCCESS;

fail:
    CleanupPerf();
    return PWR_ERR_SYS_EXCEPTION;
}

static int SetupPerfRings(void)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    g_perfMmapSize = (size_t)pageSize * (PERF_PAGE_COUNT + 1);
    for (int i = 0; i < g_perfCnt; i++) {
        void *base = mmap(NULL, g_perfMmapSize, PROT_READ | PROT_WRITE, MAP_SHARED, g_perfFd[i], 0);
        if (base == MAP_FAILED) {
            Logger(ERROR, MD_NM_LOG, "mmap perf ring cpu%d failed: %d (%s)", i, errno, strerror(errno));
            return PWR_ERR_SYS_EXCEPTION;
        }
        g_perfBase[i] = base;
    }
    return PWR_SUCCESS;
}

/* Resolve /proc/<pid>/fd/<fd> to a real path. Returns PWR_SUCCESS on success. */
static int ResolveFdPath(int pid, int fd, char *out, size_t outSize)
{
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(link, out, outSize - 1);
    if (n <= 0) {
        return PWR_ERR_COMMON;
    }
    out[n] = '\0';
    return PWR_SUCCESS;
}

/* Re-snapshot the watch paths for correlation. Called once at init. */
static void SnapshotWatchPaths(void)
{
    pthread_mutex_lock(&g_writerLock);
    g_watchPathCount = 0;
    /* Extra watch files come from the config (key drift_watch_files, kept
     * for compatibility). */
    WatchCfg *cfg = GetWatchCfg();
    if (cfg->extraFiles[0] != '\0') {
        char buf[MAX_LINE_LENGTH] = {0};
        StrCopy(buf, cfg->extraFiles, sizeof(buf));
        char *tok = strtok(buf, ",");
        while (tok != NULL && g_watchPathCount < MAX_WATCH_PATHS) {
            LRtrim(tok);
            if (tok[0] != '\0') {
                StrCopy(g_watchPaths[g_watchPathCount], tok, MAX_FULL_NAME);
                g_watchPathCount++;
            }
            tok = strtok(NULL, ",");
        }
    }
    /* Always watch the cpufreq sysfs root prefix and the other roots - any
     * write to a path starting with these is interesting. We store them as
     * prefixes and do prefix matching. */
    static const char *const builtinPrefix[] = {
        "/sys/devices/system/cpu/cpufreq/",
        "/sys/kernel/hbm_cache/",
        "/sys/devices/system/container/",
        "/sys/firmware/efi/efivars/",
    };
    for (size_t i = 0; i < sizeof(builtinPrefix) / sizeof(builtinPrefix[0]); i++) {
        if (g_watchPathCount < MAX_WATCH_PATHS) {
            StrCopy(g_watchPaths[g_watchPathCount++], builtinPrefix[i], MAX_FULL_NAME);
        }
    }
    pthread_mutex_unlock(&g_writerLock);
}

static bool PathIsWatched(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return false;
    }
    pthread_mutex_lock(&g_writerLock);
    for (int i = 0; i < g_watchPathCount; i++) {
        if (strncmp(path, g_watchPaths[i], strlen(g_watchPaths[i])) == 0) {
            pthread_mutex_unlock(&g_writerLock);
            return true;
        }
    }
    pthread_mutex_unlock(&g_writerLock);
    return false;
}

/* Push the watched path prefixes into the kernel path_prefixes map so
 * kp_open_enter can filter opens in-kernel and keep map traffic bounded.
 * Must run after the maps are created and before the open probes attach.
 * Prefixes longer than the map value are truncated: a truncated prefix can
 * over-match, never under-match, and user space re-filters every hit. */
static void PopulatePathPrefixes(void)
{
    int mapFd = FindMapFd("path_prefixes");
    if (mapFd < 0) {
        return;
    }
    pthread_mutex_lock(&g_writerLock);
    int pushed = 0;
    for (int i = 0; i < g_watchPathCount && pushed < BPF_PREFIX_SLOTS; i++) {
        char pfx[WRITER_PATH_LEN] = {0};
        size_t len = strlen(g_watchPaths[i]);
        if (len >= sizeof(pfx)) {
            Logger(WARNING, MD_NM_LOG, "Watch path longer than %d chars; prefix truncated.",
                (int)sizeof(pfx) - 1);
            len = sizeof(pfx) - 1;
        }
        memcpy(pfx, g_watchPaths[i], len);
        uint32_t key = (uint32_t)pushed;
        union bpf_attr attr;
        bzero(&attr, sizeof(attr));
        attr.map_fd = mapFd;
        attr.key = (uint64_t)(uintptr_t)&key;
        attr.value = (uint64_t)(uintptr_t)pfx;
        attr.flags = BPF_ANY;
        if ((int)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
            Logger(WARNING, MD_NM_LOG, "Push path prefix failed: %d (%s)",
                errno, strerror(errno));
        } else {
            pushed++;
        }
    }
    pthread_mutex_unlock(&g_writerLock);
    Logger(INFO, MD_NM_LOG, "Pushed %d watched path prefixes into the BPF map.", pushed);
}

/* Sweep aged fd_paths entries so the hash map cannot fill with entries of
 * dead (pid, fd) pairs over weeks of uptime. Long-lived fds do not need
 * their entries: they resolve live via /proc while they stay open. */
static void SweepFdPaths(void)
{
    int mapFd = FindMapFd("fd_paths");
    if (mapFd < 0) {
        return;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t nowNs = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;

    struct {
        uint64_t ktime;
        char path[WRITER_PATH_LEN];
    } val;
    uint64_t keyBuf;
    uint64_t next;
    const void *curKey = NULL; /* NULL key fetches the first entry */
    int swept = 0;
    for (int guard = 0; guard < 20000; guard++) {
        union bpf_attr attr;
        bzero(&attr, sizeof(attr));
        attr.map_fd = mapFd;
        attr.key = (uint64_t)(uintptr_t)curKey;
        attr.next_key = (uint64_t)(uintptr_t)&next;
        if ((int)syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) < 0) {
            break; /* end of map */
        }
        bzero(&attr, sizeof(attr));
        attr.map_fd = mapFd;
        attr.key = (uint64_t)(uintptr_t)&next;
        attr.value = (uint64_t)(uintptr_t)&val;
        if ((int)syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0 &&
            nowNs > val.ktime &&
            nowNs - val.ktime > (uint64_t)FD_SWEEP_AGE_MS * 1000000ULL) {
            bzero(&attr, sizeof(attr));
            attr.map_fd = mapFd;
            attr.key = (uint64_t)(uintptr_t)&next;
            if ((int)syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) == 0) {
                swept++;
            }
        }
        keyBuf = next;
        curKey = &keyBuf;
    }
    if (swept > 0) {
        Logger(INFO, MD_NM_LOG, "Swept %d stale fd_paths entries.", swept);
    }
}

/* Scratch for one perf record: header (16B) + raw size (4B) + payload.
 * Our WriterEvent is 184 bytes with the tracked path attached, so 512
 * covers it and any kernel-side ancillary record (e.g. PERF_RECORD_LOST). */
#define PERF_SAMPLE_MAX 512

#define WRITER_CMD_LEN 100

/* Convert the kernel-side event timestamp (bpf_ktime_get_ns, CLOCK_MONOTONIC)
 * to a wall-clock string, so audit lines carry the real write time instead of
 * the drain time (which can lag by up to the 50ms poll interval). */
static void FormatEventTime(uint64_t ktimeNs, char *out, size_t outSize)
{
    struct timespec rt;
    struct timespec mono;
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    int64_t offsetNs = (int64_t)rt.tv_sec * 1000000000LL + rt.tv_nsec -
        ((int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec);
    int64_t wallNs = (int64_t)ktimeNs + offsetNs;
    time_t sec = (time_t)(wallNs / 1000000000LL);
    long ms = (long)((wallNs % 1000000000LL) / 1000000LL);
    struct tm tmBuf;
    localtime_r(&sec, &tmBuf);
    char base[MAX_STD_TIME] = {0};
    strftime(base, sizeof(base), "%F %T", &tmBuf);
    snprintf(out, outSize, "%s.%03ld", base, ms);
}

/* Best-effort process evidence for foreign writers: /proc/<pid>/exe,
 * flattened /proc/<pid>/cmdline and the passwd name of the real uid.
 * Everything degrades to "-" when the process is already gone. The collector
 * thread is the only caller, so the uid-name cache needs no locking. */
static void EnrichWriterInfo(int pid, unsigned int uid, char *exe, size_t exeSize,
    char *cmd, size_t cmdSize, char *user, size_t userSize)
{
    exe[0] = '\0';
    cmd[0] = '\0';
    user[0] = '\0';

    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t n = readlink(link, exe, exeSize - 1);
    if (n > 0) {
        exe[n] = '\0';
    } else {
        snprintf(exe, exeSize, "-");
    }

    char procLine[64];
    snprintf(procLine, sizeof(procLine), "/proc/%d/cmdline", pid);
    int fd = open(procLine, O_RDONLY);
    if (fd >= 0) {
        char raw[WRITER_CMD_LEN] = {0};
        ssize_t rd = read(fd, raw, sizeof(raw) - 1);
        close(fd);
        if (rd > 0) {
            for (ssize_t i = 0; i < rd; i++) {
                if (raw[i] == '\0') {
                    raw[i] = ' ';
                }
            }
            snprintf(cmd, cmdSize, "%s", raw);
        }
    }
    if (cmd[0] == '\0') {
        snprintf(cmd, cmdSize, "-");
    }

    /* Single-entry uid->name cache; passwd lookups dominate the drain cost
     * otherwise (one write burst can carry hundreds of events). */
    static unsigned int cachedUid = 0;
    static bool cachedValid = false;
    static char cachedName[64] = {0};
    if (!cachedValid || cachedUid != uid) {
        struct passwd pwdBuf;
        char buf[512];
        struct passwd *pwd = NULL;
        if (getpwuid_r((uid_t)uid, &pwdBuf, buf, sizeof(buf), &pwd) == 0 &&
            pwd != NULL && pwd->pw_name != NULL) {
            snprintf(cachedName, sizeof(cachedName), "%s", pwd->pw_name);
        } else {
            snprintf(cachedName, sizeof(cachedName), "%u", uid);
        }
        cachedUid = uid;
        cachedValid = true;
    }
    snprintf(user, userSize, "%s", cachedName);
}

static void DrainPerfRing(void)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0 || g_perfCnt <= 0) {
        return;
    }
    size_t dataSize = (size_t)pageSize * PERF_PAGE_COUNT;
    size_t dataStart = (size_t)pageSize;

    for (int i = 0; i < g_perfCnt; i++) {
        if (g_perfBase[i] == NULL) {
            continue;
        }
        struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)g_perfBase[i];
        const uint8_t *ring = (const uint8_t *)g_perfBase[i] + dataStart;
        uint64_t head = __atomic_load_n(&header->data_head, __ATOMIC_ACQUIRE);
        uint64_t tail = header->data_tail;
        if (tail == head) {
            continue;
        }
        uint8_t evBuf[PERF_SAMPLE_MAX];
        while (tail < head) {
            size_t off = (size_t)(tail % dataSize);
            /* Read the 16-byte event header, honoring ring wrap-around. */
            struct perf_event_header hdr;
            size_t first = dataSize - off;
            if (first > sizeof(hdr)) {
                first = sizeof(hdr);
            }
            memcpy(&hdr, ring + off, first);
            if (first < sizeof(hdr)) {
                memcpy((uint8_t *)&hdr + first, ring, sizeof(hdr) - first);
            }
            uint16_t eSize = hdr.size;
            if (eSize < sizeof(hdr) || eSize > sizeof(evBuf)) {
                /* Malformed record: resync instead of spinning forever. */
                tail = head;
                break;
            }
            /* Copy the whole record out (also handles wrap), then advance. */
            if (off + eSize <= dataSize) {
                memcpy(evBuf, ring + off, eSize);
            } else {
                size_t f1 = dataSize - off;
                memcpy(evBuf, ring + off, f1);
                memcpy(evBuf + f1, ring, eSize - f1);
            }
            tail += eSize;

            g_statRecords++;
            if (hdr.type != PERF_RECORD_SAMPLE) {
                if (hdr.type == PERF_RECORD_LOST) {
                    g_statLost++;
                }
                continue;
            }
            /* Layout: PERF_SAMPLE_RAW = u32 size, then size bytes of raw data.
             * The event comes in two sizes: 120 bytes bare, 184 with the
             * kernel-tracked path attached. */
            const uint8_t *sample = evBuf + sizeof(struct perf_event_header);
            uint32_t rawSize = *(const uint32_t *)sample;
            const void *raw = sample + sizeof(uint32_t);
            if (rawSize < WRITER_EVENT_CORE ||
                rawSize > sizeof(evBuf) - sizeof(struct perf_event_header) - sizeof(uint32_t)) {
                g_statBadRaw++;
                continue;
            }
            g_statSamples++;
            const struct WriterEvent *ev = (const struct WriterEvent *)raw;
            char path[MAX_FULL_NAME] = {0};
            /* Prefer the kernel-tracked path: it reflects the fd state at
             * write time, which is the truth that matters even when the fd
             * was closed long before this ring got drained (the case that
             * used to drop every short-lived write). Fall back to the live
             * /proc lookup for fds the probes never saw: opened before the
             * service started or tracked past the freshness window. */
            if (ev->pathValid != 0 && rawSize >= sizeof(struct WriterEvent)) {
                char tracked[WRITER_PATH_LEN + 1] = {0};
                memcpy(tracked, ev->path, WRITER_PATH_LEN);
                StrCopy(path, tracked, sizeof(path));
                g_statTracked++;
            } else if (ResolveFdPath(ev->pid, ev->fd, path, sizeof(path)) != PWR_SUCCESS) {
                g_statResolveFail++;
                continue;
            }
            if (!PathIsWatched(path)) {
                continue;
            }
            g_statWatched++;
            /* NUL-terminate the captured buffer at bufLen for logging. */
            char val[WRITER_BUF_LEN + 1] = {0};
            uint32_t n = ev->bufLen;
            if (n > WRITER_BUF_LEN) {
                n = WRITER_BUF_LEN;
            }
            memcpy(val, ev->buf, n);

            struct WriterAudit wa;
            memset(&wa, 0, sizeof(wa));
            char ts[MAX_STD_TIME] = {0};
            FormatEventTime(ev->ktime, ts, sizeof(ts));
            wa.ts = ts;
            wa.uid = ev->uid;
            wa.pid = ev->pid;
            wa.tid = ev->tid;
            wa.comm = ev->comm;
            wa.file = path;
            wa.value = val;
            if (ev->pid != getpid()) {
                /* Foreign writer: resolve process evidence while the
                 * process is still around. */
                char exe[MAX_FULL_NAME] = {0};
                char cmd[WRITER_CMD_LEN + 1] = {0};
                char user[64] = {0};
                EnrichWriterInfo(ev->pid, ev->uid, exe, sizeof(exe),
                    cmd, sizeof(cmd), user, sizeof(user));
                wa.exe = exe;
                wa.cmd = cmd;
                wa.userName = user;
            }
            AuditWriterEvent(&wa);
        }
        __atomic_store_n(&header->data_tail, tail, __ATOMIC_RELEASE);
    }
}

static void *WriterCollectorLoop(void *arg)
{
    (void)arg;
    unsigned int ticks = 0;
    while (g_writerThread.keepRunning) {
        DrainPerfRing();
        /* Close any aggregated WRITER run that received no event in this
         * pass, so a quiet fan-out still reaches the file promptly. */
        AuditWriterTickFlush();
        /* ~30s at the 50ms poll interval: age out fd_paths entries of
         * fds that are long gone so the hash map cannot fill up. */
        if (++ticks % 600 == 0) {
            SweepFdPaths();
        }
        /* ~20s: periodic stats for field diagnosis. */
        if (ticks % 400 == 0) {
            Logger(INFO, MD_NM_LOG,
                "Writer stats: records=%llu lost=%llu samples=%llu badRaw=%llu "
                "resolveFail=%llu tracked=%llu watched=%llu fdTracking=%d",
                (unsigned long long)g_statRecords, (unsigned long long)g_statLost,
                (unsigned long long)g_statSamples, (unsigned long long)g_statBadRaw,
                (unsigned long long)g_statResolveFail, (unsigned long long)g_statTracked,
                (unsigned long long)g_statWatched, g_fdTracking);
        }
        usleep(50 * 1000); /* 50ms poll interval - event latency is acceptable for audit */
    }
    return NULL;
}

/* Close the program and map fds of a loaded (but not necessarily attached)
 * object; used by init failure paths while the collector is not running. */
static void CloseLoadedObjects(void)
{
    for (int i = 0; i < g_bpfProgCnt; i++) {
        if (g_bpfProgs[i].progFd >= 0) {
            close(g_bpfProgs[i].progFd);
            g_bpfProgs[i].progFd = -1;
        }
    }
    g_bpfProgCnt = 0;
    for (int i = 0; i < g_bpfMapCnt; i++) {
        if (g_bpfMapFds[i] >= 0) {
            close(g_bpfMapFds[i]);
            g_bpfMapFds[i] = -1;
        }
    }
    g_bpfMapCnt = 0;
    g_bpfMapFd = -1;
    g_fdTracking = 0;
}

int InitBpfWriter(void)
{
    if (!GetBpfCfg()->enable) {
        /* Writer attribution can be independently disabled by config. */
        Logger(INFO, MD_NM_LOG, "BPF writer disabled by config.");
        return PWR_SUCCESS;
    }

    /* Raise memlock so the BPF program can be loaded. */
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        Logger(WARNING, MD_NM_LOG, "setrlimit MEMLOCK failed: %d (%s)", errno, strerror(errno));
    }

    SnapshotWatchPaths();

    int ret = LoadBpfObject();
    if (ret != PWR_SUCCESS) {
        return PWR_SUCCESS; /* best-effort */
    }
    /* Prefixes must be in the map before the open probes attach, or every
     * open in the window between attach and update would slip by untracked. */
    PopulatePathPrefixes();
    ret = AttachPerCpu();
    if (ret != PWR_SUCCESS) {
        CloseLoadedObjects();
        return PWR_SUCCESS; /* best-effort */
    }
    ret = SetupPerfRings();
    if (ret != PWR_SUCCESS) {
        CleanupPerf();
        CloseLoadedObjects();
        return PWR_SUCCESS; /* best-effort */
    }

    g_writerEnabled = 1;
    InitThreadInfo(&g_writerThread);
    ret = CreateThread(&g_writerThread, WriterCollectorLoop, NULL);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_LOG, "Create writer collector thread failed. ret:%d", ret);
        ClearBpfWriter();
        return PWR_SUCCESS;
    }
    Logger(INFO, MD_NM_LOG, "BPF writer attribution started. watching %d path prefixes.",
        g_watchPathCount);
    return PWR_SUCCESS;
}

/* Release all per-CPU perf fds and their mmap'd rings, every tracepoint
 * carrier, and the probes registered in kprobe_events. */
static void CleanupPerf(void)
{
    for (int i = 0; i < MAX_CPUS; i++) {
        if (g_perfBase[i] != NULL && g_perfBase[i] != MAP_FAILED) {
            munmap(g_perfBase[i], g_perfMmapSize);
        }
        g_perfBase[i] = NULL;
        if (g_perfFd[i] >= 0) {
            (void)ioctl(g_perfFd[i], PERF_EVENT_IOC_DISABLE, 0);
            close(g_perfFd[i]);
            g_perfFd[i] = -1;
        }
    }
    g_perfCnt = 0;
    g_perfMmapSize = 0;
    /* The kernel only accepts the probe deletion once every referencing perf
     * fd is closed, hence after the loops above. */
    for (int i = 0; i < g_bpfProgCnt; i++) {
        DetachOneProbe(&g_bpfProgs[i]);
    }
}

void ClearBpfWriter(void)
{
    if (!g_writerEnabled) {
        return;
    }
    FiniThreadInfo(&g_writerThread);
    CleanupPerf();
    CloseLoadedObjects();
    g_writerEnabled = 0;
}
