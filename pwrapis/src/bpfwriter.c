/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * Description: loader/collector implementation for the writer-attribution
 *              eBPF program. Uses the raw bpf() syscall and a hand-rolled
 *              ELF parser for the BPF object, so no libbpf dependency is
 *              required. Path resolution for each write's fd is done in user
 *              space via /proc/<pid>/fd/<fd>, which keeps the BPF program
 *              kernel-version independent.
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

/* Must match struct WriterEvent in bpf_writer.bpf.c. */
#define WRITER_BUF_LEN 64
#define WRITER_COMM_LEN 16
struct WriterEvent {
    unsigned int uid;
    int pid;
    int tid;
    char comm[WRITER_COMM_LEN];
    int fd;
    unsigned int bufLen;
    char buf[WRITER_BUF_LEN];
    uint64_t ktime; /* bpf_ktime_get_ns() at write entry (CLOCK_MONOTONIC) */
};

#define BPF_KPROBE_FUNC "ksys_write"
#define BPF_PROG_NAME "kp_ksys_write"
/* Name of the kprobe registered in tracefs kprobe_events. The probe provides
 * the tracepoint id used to open the perf event that carries the program. */
#define KPROBE_EVENT_NAME "pwraudit_write"
#define PERF_PAGE_COUNT 64
#define PERF_WATERMARK 1
#define MAX_WATCH_PATHS 64
/* Upper bound of monitored CPUs. The perf-event-array map is indexed by CPU
 * id, so its max_entries must be >= the highest monitored CPU index; both
 * derive from the online CPU count clamped here. */
#define MAX_CPUS 1024

static int g_bpfProgFd = -1;
static int g_bpfMapFd = -1;
/* One tracepoint perf fd (cpu0) carries the BPF program; one BPF_OUTPUT ring
 * fd per online CPU is registered in the perf-event-array map. */
static int g_tpFd = -1;
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
static uint64_t g_statWatched;

static void CleanupPerf(void);

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

/* The verifier log is multi-line. Flatten it onto a single log line so the
 * full trace survives grep filters (which previously hid all but the first
 * insn line and made the failure look like a 1-line mystery). */
static void FlattenVerifierLog(const char *log, char *out, size_t outSize)
{
    size_t o = 0;
    for (size_t i = 0; log != NULL && log[i] != '\0' && o + 1 < outSize; i++) {
        out[o++] = (log[i] == '\n') ? '|' : log[i];
    }
    out[o] = '\0';
}

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

/* Parse the BPF ELF object, create the perf-event-array map it references,
 * apply relocations (patch map fds into ld_imm64 instructions) and load the
 * program. On success sets g_bpfProgFd. Returns PWR_SUCCESS or an error. */
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

    /* 1. Locate the program section (sections starting with kprobe/ are
     *    preferred; .text is the fallback). */
    int progSecIdx = -1;
    int textSecIdx = -1;
    for (int i = 0; i < eh->shnum; i++) {
        if (shdrs[i].type != 1) { /* SHT_PROGBITS */
            continue;
        }
        const char *name = strtab + shdrs[i].name;
        if (strncmp(name, "kprobe/", 7) == 0 && shdrs[i].size > 0) {
            progSecIdx = i;
            break;
        }
        if (strcmp(name, ".text") == 0) {
            textSecIdx = i;
        }
    }
    if (progSecIdx < 0 && textSecIdx >= 0 && shdrs[textSecIdx].size > 0) {
        progSecIdx = textSecIdx;
    }
    if (progSecIdx < 0) {
        Logger(ERROR, MD_NM_LOG, "No BPF program section found.");
        return PWR_ERR_COMMON;
    }
    const struct Shdr *progSh = &shdrs[progSecIdx];
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

    /* 2. Create the perf-event-array map the program references. We create
     *    one unconditionally; if the program has no map reference the fd is
     *    simply unused. */
    union bpf_attr mapAttr;
    bzero(&mapAttr, sizeof(mapAttr));
    mapAttr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    mapAttr.key_size = sizeof(int);
    mapAttr.value_size = sizeof(int);
    /* The map is indexed by CPU id (BPF_F_CURRENT_CPU), so max_entries must
     * cover every CPU we may attach a perf event to: min(online, MAX_CPUS). */
    long nCpu = sysconf(_SC_NPROCESSORS_ONLN);
    mapAttr.max_entries =
        (uint32_t)(((nCpu > MAX_CPUS) || (nCpu <= 0)) ? MAX_CPUS : nCpu);
    int mapFd = (int)syscall(__NR_bpf, BPF_MAP_CREATE, &mapAttr, sizeof(mapAttr));
    if (mapFd < 0) {
        Logger(ERROR, MD_NM_LOG, "BPF_MAP_CREATE failed: %d (%s)", errno, strerror(errno));
        free(insns);
        return PWR_ERR_SYS_EXCEPTION;
    }

    /* 3. Apply relocations from the .rel<progsec> section: for each relocation
     *    that targets a symbol defined in a .maps section, patch the ld_imm64
     *    instruction at the relocation offset with the map fd. */
    char relaName[32];
    snprintf(relaName, sizeof(relaName), ".rela%s", strtab + progSh->name);
    /* Also accept the clang-emitted short form ".rel" + section name. */
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
            insns[insnIdx].imm = mapFd;
            insns[insnIdx + 1].imm = 0;
        }
        break;
    }

    /* 4. Load the program with the (possibly patched) instructions. */
    char logBuf[65536] = {0};
    union bpf_attr attr;
    bzero(&attr, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insns = (uint64_t)insns;
    attr.insn_cnt = (uint32_t)insnCnt;
    attr.license = (uint64_t)"GPL";
    attr.log_buf = (uint64_t)logBuf;
    attr.log_size = sizeof(logBuf);
    attr.log_level = 1;

    int progFd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (progFd < 0) {
        int savedErrno = errno;
        char flat[1600];
        FlattenVerifierLog(logBuf, flat, sizeof(flat));
        Logger(ERROR, MD_NM_LOG, "BPF_PROG_LOAD failed: %d (%s). insnCnt:%u verifier: %s",
            savedErrno, strerror(savedErrno), (unsigned)insnCnt, flat);
        /* Retry once with log_level=2 for a fuller verifier trace. */
        attr.log_level = 2;
        (void)memset(logBuf, 0, sizeof(logBuf));
        int fd2 = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
        if (fd2 >= 0) {
            close(fd2);
            Logger(WARNING, MD_NM_LOG, "BPF_PROG_LOAD retry(log_level=2) unexpectedly succeeded.");
        } else {
            char flat2[2400];
            FlattenVerifierLog(logBuf, flat2, sizeof(flat2));
            Logger(ERROR, MD_NM_LOG, "BPF_PROG_LOAD retry(log_level=2): %d (%s). verifier: %s",
                errno, strerror(errno), flat2);
        }
        RunLoadProbe();
        free(insns);
        close(mapFd);
        return PWR_ERR_SYS_EXCEPTION;
    }
    free(insns);
    /* Keep the map fd for the collector; closing it after attach is fine since
     * the kernel holds a reference, but retain it for clarity. */
    g_bpfMapFd = mapFd;
    g_bpfProgFd = progFd;
    Logger(INFO, MD_NM_LOG, "BPF writer program loaded. progFd:%d mapFd:%d", progFd, mapFd);
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

/* Delete our kprobe from kprobe_events. Only succeeds after every perf fd
 * referencing the event is closed (otherwise the kernel refuses with EBUSY);
 * CleanupPerf therefore closes the fds first. Best-effort: a failure here
 * only leaves a harmless unused probe behind. */
static void RemoveKprobeEvent(void)
{
    char traceDir[MAX_FULL_NAME];
    char cmd[64];
    if (!FindTracefsDir(traceDir, sizeof(traceDir))) {
        return;
    }
    (void)snprintf(cmd, sizeof(cmd), "-:%s", KPROBE_EVENT_NAME);
    if (WriteTraceCmd(traceDir, "kprobe_events", cmd) != PWR_SUCCESS) {
        Logger(WARNING, MD_NM_LOG, "Remove kprobe event %s failed: %d (%s)",
            KPROBE_EVENT_NAME, errno, strerror(errno));
    }
}

/* Attach the writer probe with the classic kprobe_events + tracepoint path
 * (the model bcc/libbpf use on 5.x):
 *
 *   1. Register a kprobe named pwraudit_write on ksys_write via
 *      <tracefs>/kprobe_events, then read the auto-assigned tracepoint id
 *      from events/kprobes/pwraudit_write/id.
 *   2. Open ONE tracepoint perf event (cpu0) and attach the loaded program
 *      with PERF_EVENT_IOC_SET_BPF. Opening the event enables the underlying
 *      kprobe (TRACE_REG_PERF_REGISTER -> TP_FLAG_PROFILE + enable_kprobe),
 *      and SET_BPF installs the program into the kprobe event's shared
 *      prog_array, so the program runs on every CPU where the kprobe fires.
 *      No per-CPU kprobe fds are needed for the BPF output.
 *   3. Open one PERF_COUNT_SW_BPF_OUTPUT software ring per CPU and register
 *      it in the perf-event-array map at the CPU index - exactly where the
 *      program's bpf_perf_event_output(BPF_F_CURRENT_CPU) looks the ring up.
 *
 * The kprobe PMU used previously is not viable: it does not exist in mainline
 * 5.10 trace_kprobe.c (vendor backports open fine but never enable the probe
 * into the perf/BPF path), and its fds are rejected by
 * __bpf_perf_event_output (-EINVAL) because they are not
 * PERF_COUNT_SW_BPF_OUTPUT software events, so the ring stayed empty.
 *
 * pid = -1 so writes from every process are captured. Requires root /
 * CAP_PERFMON plus CONFIG_KPROBE_EVENTS; on failure the caller degrades
 * gracefully. */
static int AttachPerCpu(void)
{
    char traceDir[MAX_FULL_NAME];
    char cmd[128];
    /* traceDir can fill MAX_FULL_NAME; the suffix needs extra room. */
    char idPath[MAX_FULL_NAME + 64];
    struct perf_event_attr pea;

    if (!FindTracefsDir(traceDir, sizeof(traceDir))) {
        Logger(ERROR, MD_NM_LOG, "tracefs kprobe_events not found (tracefs not mounted?). "
            "Writer attribution disabled.");
        return PWR_ERR_SYS_EXCEPTION;
    }

    /* Best-effort cleanup of a stale probe left by a crashed previous run;
     * an existing probe would make the registration below fail with EEXIST. */
    (void)snprintf(cmd, sizeof(cmd), "-:%s", KPROBE_EVENT_NAME);
    (void)WriteTraceCmd(traceDir, "kprobe_events", cmd);

    (void)snprintf(cmd, sizeof(cmd), "p:%s %s", KPROBE_EVENT_NAME, BPF_KPROBE_FUNC);
    if (WriteTraceCmd(traceDir, "kprobe_events", cmd) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_LOG, "Register kprobe '%s' failed: %d (%s). "
            "Need CONFIG_KPROBE_EVENTS and a kprobe-able %s.",
            cmd, errno, strerror(errno), BPF_KPROBE_FUNC);
        return PWR_ERR_SYS_EXCEPTION;
    }

    (void)snprintf(idPath, sizeof(idPath), "%s/events/kprobes/%s/id",
        traceDir, KPROBE_EVENT_NAME);
    unsigned int tpId = 0;
    FILE *fp = fopen(idPath, "r");
    if (fp != NULL && fscanf(fp, "%u", &tpId) != 1) {
        tpId = 0;
    }
    if (fp != NULL) {
        fclose(fp);
    }
    if (tpId == 0) {
        Logger(ERROR, MD_NM_LOG, "Cannot read tracepoint id from %s.", idPath);
        RemoveKprobeEvent();
        return PWR_ERR_SYS_EXCEPTION;
    }

    int cpuCnt = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cpuCnt <= 0) {
        Logger(ERROR, MD_NM_LOG, "Invalid online cpu count %d.", cpuCnt);
        RemoveKprobeEvent();
        return PWR_ERR_SYS_EXCEPTION;
    }
    if (cpuCnt > MAX_CPUS) {
        Logger(WARNING, MD_NM_LOG, "Online cpus %d exceed %d; only the first %d are monitored.",
            cpuCnt, MAX_CPUS, MAX_CPUS);
        cpuCnt = MAX_CPUS;
    }

    /* One ring fd per monitored CPU plus the carrier fd; make sure the fd
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

    /* 1. The prog carrier: one tracepoint perf event on cpu0. */
    bzero(&pea, sizeof(pea));
    pea.type = PERF_TYPE_TRACEPOINT;
    pea.size = sizeof(pea);
    pea.config = tpId;
    pea.sample_period = 1;                 /* record every hit */
    pea.sample_type = PERF_SAMPLE_RAW;
    pea.wakeup_events = PERF_WATERMARK;
    pea.disabled = 1;
    g_tpFd = (int)syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
    if (g_tpFd < 0) {
        Logger(WARNING, MD_NM_LOG, "perf_event_open tracepoint %s/%u cpu0 failed: %d (%s). "
            "Writer attribution disabled (need root / CAP_PERFMON).",
            KPROBE_EVENT_NAME, tpId, errno, strerror(errno));
        goto fail;
    }
    if (ioctl(g_tpFd, PERF_EVENT_IOC_SET_BPF, g_bpfProgFd) < 0) {
        Logger(ERROR, MD_NM_LOG, "PERF_EVENT_IOC_SET_BPF failed: %d (%s)", errno, strerror(errno));
        goto fail;
    }

    /* 2. One BPF_OUTPUT software ring per CPU, registered in the map. */
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

    /* 3. Enable the carrier and all rings together. */
    if (ioctl(g_tpFd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        Logger(ERROR, MD_NM_LOG, "PERF_EVENT_IOC_ENABLE carrier failed: %d (%s)",
            errno, strerror(errno));
        goto fail;
    }
    for (int i = 0; i < cpuCnt; i++) {
        if (ioctl(g_perfFd[i], PERF_EVENT_IOC_ENABLE, 0) < 0) {
            Logger(ERROR, MD_NM_LOG, "PERF_EVENT_IOC_ENABLE cpu%d failed: %d (%s)",
                i, errno, strerror(errno));
            goto fail;
        }
    }

    g_perfCnt = cpuCnt;
    Logger(INFO, MD_NM_LOG, "Kprobe/ksys_write attached: probe %s (tp id %u) carrier on cpu0, "
        "%d BPF_OUTPUT rings enabled.", KPROBE_EVENT_NAME, tpId, cpuCnt);
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
    /* Always watch the cpufreq sysfs root prefix and HBM state roots - any
     * write to a path starting with these is interesting. We store them as
     * prefixes and do prefix matching. */
    if (g_watchPathCount < MAX_WATCH_PATHS) {
        StrCopy(g_watchPaths[g_watchPathCount++], "/sys/devices/system/cpu/cpufreq/", MAX_FULL_NAME);
    }
    if (g_watchPathCount < MAX_WATCH_PATHS) {
        StrCopy(g_watchPaths[g_watchPathCount++], "/sys/kernel/hbm_cache/", MAX_FULL_NAME);
    }
    if (g_watchPathCount < MAX_WATCH_PATHS) {
        StrCopy(g_watchPaths[g_watchPathCount++], "/sys/devices/system/container/", MAX_FULL_NAME);
    }
    if (g_watchPathCount < MAX_WATCH_PATHS) {
        StrCopy(g_watchPaths[g_watchPathCount++], "/sys/firmware/efi/efivars/", MAX_FULL_NAME);
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

/* Scratch for one perf record: header (16B) + raw size (4B) + payload.
 * Our WriterEvent is 112 bytes, so 512 covers it and any kernel-side
 * ancillary record (e.g. PERF_RECORD_LOST). */
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
            /* Layout: PERF_SAMPLE_RAW = u32 size, then size bytes of raw data. */
            const uint8_t *sample = evBuf + sizeof(struct perf_event_header);
            uint32_t rawSize = *(const uint32_t *)sample;
            const void *raw = sample + sizeof(uint32_t);
            if (rawSize < sizeof(struct WriterEvent) ||
                rawSize > sizeof(evBuf) - sizeof(struct perf_event_header) - sizeof(uint32_t)) {
                g_statBadRaw++;
                continue;
            }
            g_statSamples++;
            const struct WriterEvent *ev = (const struct WriterEvent *)raw;
            char path[MAX_FULL_NAME] = {0};
            if (ResolveFdPath(ev->pid, ev->fd, path, sizeof(path)) != PWR_SUCCESS) {
                g_statResolveFail++;
                continue;
            }
            if (!PathIsWatched(path)) {
                continue;
            }
            g_statWatched++;
            {
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
        /* ~20s at the 50ms poll interval: periodic stats for field diagnosis. */
        if (++ticks >= 400) {
            ticks = 0;
            Logger(INFO, MD_NM_LOG,
                "Writer stats: records=%llu lost=%llu samples=%llu badRaw=%llu resolveFail=%llu watched=%llu",
                (unsigned long long)g_statRecords, (unsigned long long)g_statLost,
                (unsigned long long)g_statSamples, (unsigned long long)g_statBadRaw,
                (unsigned long long)g_statResolveFail, (unsigned long long)g_statWatched);
        }
        usleep(50 * 1000); /* 50ms poll interval - event latency is acceptable for audit */
    }
    return NULL;
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
    ret = AttachPerCpu();
    if (ret != PWR_SUCCESS) {
        close(g_bpfProgFd);
        g_bpfProgFd = -1;
        return PWR_SUCCESS; /* best-effort */
    }
    ret = SetupPerfRings();
    if (ret != PWR_SUCCESS) {
        CleanupPerf();
        close(g_bpfProgFd);
        g_bpfProgFd = -1;
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

/* Release all per-CPU perf fds and their mmap'd rings, the tracepoint carrier
 * fd, and the kprobe registered in kprobe_events. */
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
    if (g_tpFd >= 0) {
        (void)ioctl(g_tpFd, PERF_EVENT_IOC_DISABLE, 0);
        close(g_tpFd);
        g_tpFd = -1;
    }
    /* The kernel only accepts the probe deletion once every referencing perf
     * fd is closed, hence after the loops above. */
    RemoveKprobeEvent();
}

void ClearBpfWriter(void)
{
    if (!g_writerEnabled) {
        return;
    }
    FiniThreadInfo(&g_writerThread);
    CleanupPerf();
    if (g_bpfProgFd >= 0) {
        close(g_bpfProgFd);
        g_bpfProgFd = -1;
    }
    if (g_bpfMapFd >= 0) {
        close(g_bpfMapFd);
        g_bpfMapFd = -1;
    }
    g_writerEnabled = 0;
}
