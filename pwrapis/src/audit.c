/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: provide audit log service. Audit records answer "who did
 *              what at what time": client CONN/DISCONN lines, setting
 *              requests as REQ/RSP pairs correlated by seqId, and WRITER
 *              lines attributing every write to a watched sysfs file - to
 *              the in-flight API call when the service itself writes, to
 *              the writing process (uid/pid/exe/cmd) otherwise. Records go
 *              to <log_path>/audit.log, rotated by size, independent of
 *              log level.
 * **************************************************************************** */
#include "audit.h"

#include <dirent.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"
#include "config.h"
#include "log.h"
#include "pwrdata.h"
#include "pwrerr.h"
#include "utils.h"

#define AUDIT_FILE_NAME "audit.log"
#define AUDIT_BKP_PFX "audit.log-"
#define AUDIT_MAX_FILE_SIZE (10ULL * 1024 * 1024) // bytes
#define AUDIT_MAX_BKP_CNT 5
#define AUDIT_MAX_LINE_LEN 1024
#define AUDIT_MAX_PARAM_LEN 512
#define AUDIT_MAX_ITEMS_IN_PARAM 8
#define AUDIT_DIR_MODE 0700
/* The manual promises audit.log mode 644 so non-root auditors can read it. */
#define AUDIT_FILE_MODE 0644

static FILE *g_auditFile = NULL;
static uint64_t g_auditSize = 0;
static pthread_mutex_t g_auditLock = PTHREAD_MUTEX_INITIALIZER;

/* ---- in-flight call registry ------------------------------------------- */
/* AuditSettingReq registers a call, AuditCallBegin binds it to the executing
 * thread, AuditCallEnd/AuditSettingRsp stamp the finish time. WRITER events
 * from the service itself resolve their (opt, seq, user) context through
 * this table by the captured thread id (exact), while the call is in flight
 * or within the grace window after it finished. Unmatched service writes
 * are recorded without call context (user=- uid=- opt=- seq=-). */
#define AUDIT_MAX_INFLIGHT 32
/* How long a finished call stays attributable: the collector drains the
 * BPF perf rings on a 50ms poll, so the writes of a call that completed
 * in a few milliseconds are often harvested AFTER the call finished and
 * the RSP went out. Keep finished calls (thread binding included) for a
 * grace window so those late-drained events still carry opt/seq/user. */
#define AUDIT_CALL_GRACE_MS 1000
struct InflightCall {
    int used;
    int hasTid;          /* AuditCallBegin seen for this call */
    pid_t tid;
    uint32_t seq;
    uint16_t optType;
    uid_t uid;
    char user[MAX_NAME];
    long long startMs;
    long long endMs;     /* call finished executing; 0 = still in flight */
};
static struct InflightCall g_calls[AUDIT_MAX_INFLIGHT];
static pthread_mutex_t g_callLock = PTHREAD_MUTEX_INITIALIZER;

static long long NowMs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
}

/* Find a slot for a new call: a free one, then one whose correlation
 * grace has expired, then the oldest finished one, finally the oldest
 * in-flight one (dropped correlation is preferred over a blocked audit
 * path - the table is large enough that this is a pathological case). */
static struct InflightCall *AcquireCallSlot(void)
{
    long long now = NowMs();
    struct InflightCall *oldestDone = NULL;
    struct InflightCall *oldestAny = NULL;
    long long doneT = 0;
    long long anyT = 0;
    for (int i = 0; i < AUDIT_MAX_INFLIGHT; i++) {
        struct InflightCall *c = &g_calls[i];
        if (!c->used) {
            return c;
        }
        if (c->endMs != 0 && now - c->endMs >= AUDIT_CALL_GRACE_MS) {
            return c; /* correlation window over: safe to reuse */
        }
        if (c->endMs != 0) {
            if (oldestDone == NULL || c->endMs < doneT) {
                oldestDone = c;
                doneT = c->endMs;
            }
        } else if (oldestAny == NULL || c->startMs < anyT) {
            oldestAny = c;
            anyT = c->startMs;
        }
    }
    return (oldestDone != NULL) ? oldestDone : oldestAny;
}

static struct InflightCall *FindCall(uint32_t seq, uint16_t optType)
{
    for (int i = 0; i < AUDIT_MAX_INFLIGHT; i++) {
        if (g_calls[i].used && g_calls[i].seq == seq && g_calls[i].optType == optType) {
            return &g_calls[i];
        }
    }
    return NULL;
}

typedef struct AuditOptName {
    uint16_t optType;
    const char *apiName;
} AuditOptName;

/* Setting interfaces (and control-auth requests) that are audited. */
static const AuditOptName g_auditOptNames[] = {
    {COM_REQUEST_CONTROL_AUTH, "PWR_RequestControlAuth"},
    {COM_RELEASE_CONTROL_AUTH, "PWR_ReleaseControlAuth"},
    {SYS_SET_POWER_STATE, "PWR_SYS_SetPowerState"},
    {CPU_SET_FREQ_RANGE, "PWR_CPU_SetFreqRange"},
    {CPU_SET_FREQ_GOVERNOR, "PWR_CPU_SetFreqGovernor"},
    {CPU_SET_FREQ_GOV_ATTR, "PWR_CPU_SetFreqGovAttr"},
    {CPU_SET_CUR_FREQ, "PWR_CPU_SetFreq"},
    {CPU_SET_IDLE_GOV, "PWR_CPU_SetIdleGovernor"},
    {CPU_SET_DMA_LATENCY, "PWR_CPU_DmaSetLatency"},
    {PROC_SET_WATT_STATE, "PWR_PROC_SetWattState"},
    {PROC_SET_WATT_FIRST_DOMAIN, "PWR_PROC_SetWattFirstDomain"},
    {PROC_SET_WATT_ARRTS, "PWR_PROC_SetWattAttrs"},
    {PROC_ADD_WATT_PROCS, "PWR_PROC_AddWattProcs"},
    {PROC_DEL_WATT_PROCS, "PWR_PROC_DelWattProcs"},
    {PROC_SET_SMART_GRID_STATE, "PWR_PROC_SetSmartGridState"},
    {PROC_SET_SMART_GRID_PROCS_LEVEL, "PWR_PROC_SetSmartGridLevel"},
    {PROC_SET_SMART_GRID_GOV, "PWR_PROC_SetSmartGridGov"},
    {PROC_SET_SERVICE_STATE, "PWR_PROC_SetServiceState"},
    {HBM_SET_ALL_POWER_STATE, "PWR_HBM_SetAllPwrState"},
};

static int FindAuditOptIdx(uint16_t optType)
{
    for (size_t i = 0; i < sizeof(g_auditOptNames) / sizeof(g_auditOptNames[0]); i++) {
        if (g_auditOptNames[i].optType == optType) {
            return (int)i;
        }
    }
    return -1;
}

static const char *GetAuditOptName(uint16_t optType)
{
    int idx = FindAuditOptIdx(optType);
    return (idx >= 0) ? g_auditOptNames[idx].apiName : "UNKNOWN";
}

int IsAuditOpt(uint16_t optType)
{
    return (FindAuditOptIdx(optType) >= 0) ? PWR_TRUE : PWR_FALSE;
}

/* Escape non-printable bytes so audit lines stay single-line while control
 * characters remain recognisable: \n, \t and \r get letter forms, every
 * other byte outside 0x20..0x7e becomes \xNN. Returns the number of escape
 * sequences written (0 = plain printable text). */
static size_t EscapeStr(char *dst, size_t dstSize, const char *src, size_t srcLen)
{
    static const char hex[] = "0123456789abcdef";
    size_t out = 0;
    size_t escapes = 0;
    if (dstSize == 0) {
        return 0;
    }
    for (size_t i = 0; i < srcLen; i++) {
        unsigned char c = (unsigned char)src[i];
        char tmp[4];
        size_t n;
        if (c == '\n') {
            tmp[0] = '\\';
            tmp[1] = 'n';
            n = 2;
        } else if (c == '\t') {
            tmp[0] = '\\';
            tmp[1] = 't';
            n = 2;
        } else if (c == '\r') {
            tmp[0] = '\\';
            tmp[1] = 'r';
            n = 2;
        } else if (c >= 0x20 && c <= 0x7e) {
            tmp[0] = (char)c;
            n = 1;
        } else {
            tmp[0] = '\\';
            tmp[1] = 'x';
            tmp[2] = hex[c >> 4];
            tmp[3] = hex[c & 0x0f];
            n = 4;
        }
        if (out + n >= dstSize) {
            break; /* truncated; keep room for the NUL */
        }
        if (n > 1) {
            escapes++;
        }
        memcpy(&dst[out], tmp, n);
        out += n;
    }
    dst[out] = '\0';
    return escapes;
}

/* Escape one NUL-terminated string field into dst ("", a "-", "-" style
 * fallback stays with the caller). Bounded by the destination buffer. */
static void EscField(char *dst, size_t dstSize, const char *src)
{
    if (dstSize == 0) {
        return;
    }
    dst[0] = '\0';
    if (src != NULL) {
        (void)EscapeStr(dst, dstSize, src, strnlen(src, dstSize - 1));
    }
}

/* Bounded string copy, snprintf("%s") semantics without the format scan. */
static void SetStr(char *dst, size_t dstSize, const char *src)
{
    (void)snprintf(dst, dstSize, "%s", src);
}

/* Copy at most dataLen bytes into dst, always NUL-terminated with
 * non-printable bytes escaped. The payload of string parameters usually
 * carries a trailing NUL, which must not be escaped into a visible form. */
static void CopyDataStr(char *dst, size_t dstSize, const char *data, uint32_t dataLen)
{
    if (dst == NULL || dstSize == 0) {
        return;
    }
    dst[0] = '\0';
    if (data == NULL || dataLen == 0) {
        return;
    }
    size_t n = ((size_t)dataLen < dstSize) ? (size_t)dataLen : dstSize;
    /* Stop at an embedded NUL like a plain string copy would. */
    const char *end = memchr(data, '\0', n);
    if (end != NULL) {
        n = (size_t)(end - data);
    }
    EscapeStr(dst, dstSize, data, n);
}

static void AppendStr(char *buf, size_t bufSize, int *pos, const char *fmt, ...)
{
    if (*pos < 0 || (size_t)(*pos) + 1 >= bufSize) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buf + *pos, bufSize - (size_t)(*pos), fmt, args);
    va_end(args);
    if (ret < 0) {
        return;
    }
    if ((size_t)(*pos) + (size_t)ret >= bufSize) {
        *pos = (int)(bufSize - 1); // truncated, no more room
        return;
    }
    *pos += ret;
}

static const char *StateToStr(int state)
{
    if (state == PWR_ENABLE) {
        return "enable";
    }
    if (state == PWR_DISABLE) {
        return "disable";
    }
    return "unknown";
}

/* Append a bounded pid list, e.g. "procs=[123,456,...]" */
static void AppendPidList(char *param, size_t paramSize, int *pos, const pid_t *procs, uint32_t num)
{
    AppendStr(param, paramSize, pos, "procs=[");
    for (uint32_t i = 0; i < num && i < AUDIT_MAX_ITEMS_IN_PARAM; i++) {
        AppendStr(param, paramSize, pos, "%s%d", (i == 0) ? "" : ",", procs[i]);
    }
    AppendStr(param, paramSize, pos, "%s]", (num > AUDIT_MAX_ITEMS_IN_PARAM) ? ",..." : "");
}

/*
 * BuildParamStr - decode the request data of an audited operation into a
 * human-readable parameter string. Unknown or malformed payloads fall back
 * to "dataLen=<n>" so raw binary never enters the audit file.
 */
static void BuildParamStr(uint16_t optType, const char *data, uint32_t dataLen, char *param, size_t paramSize)
{
    int pos = 0;
    param[0] = '\0';

    if (data == NULL || dataLen == 0) {
        AppendStr(param, paramSize, &pos, "dataLen=%u", dataLen);
        return;
    }

    switch (optType) {
        case CPU_SET_CUR_FREQ: {
            if (dataLen % sizeof(PWR_CPU_CurFreq) != 0) {
                break;
            }
            uint32_t num = dataLen / sizeof(PWR_CPU_CurFreq);
            const PWR_CPU_CurFreq *freq = (const PWR_CPU_CurFreq *)data;
            AppendStr(param, paramSize, &pos, "freq=[");
            for (uint32_t i = 0; i < num && i < AUDIT_MAX_ITEMS_IN_PARAM; i++) {
                AppendStr(param, paramSize, &pos, "%s{policy%d:%.0fMHz}", (i == 0) ? "" : ",",
                    freq[i].policyId, freq[i].curFreq);
            }
            AppendStr(param, paramSize, &pos, "%s]", (num > AUDIT_MAX_ITEMS_IN_PARAM) ? ",..." : "");
            return;
        }
        case CPU_SET_FREQ_GOVERNOR:
        case CPU_SET_IDLE_GOV: {
            char gov[PWR_MAX_ELEMENT_NAME_LEN + 1] = {0};
            CopyDataStr(gov, sizeof(gov), data, dataLen);
            AppendStr(param, paramSize, &pos, "governor=\"%s\"", gov);
            return;
        }
        case CPU_SET_FREQ_GOV_ATTR: {
            if (dataLen < sizeof(PWR_CPU_FreqGovAttr)) {
                break;
            }
            const PWR_CPU_FreqGovAttr *attr = (const PWR_CPU_FreqGovAttr *)data;
            char gov[PWR_MAX_ELEMENT_NAME_LEN + 1] = {0};
            char key[PWR_MAX_ELEMENT_NAME_LEN + 1] = {0};
            char value[PWR_MAX_VALUE_LEN + 1] = {0};
            CopyDataStr(gov, sizeof(gov), attr->gov, sizeof(attr->gov));
            CopyDataStr(key, sizeof(key), attr->attr.key, sizeof(attr->attr.key));
            CopyDataStr(value, sizeof(value), attr->attr.value, sizeof(attr->attr.value));
            AppendStr(param, paramSize, &pos, "gov=\"%s\" key=\"%s\" value=\"%s\"", gov, key, value);
            return;
        }
        case CPU_SET_FREQ_RANGE: {
            if (dataLen < sizeof(PWR_CPU_FreqRange)) {
                break;
            }
            const PWR_CPU_FreqRange *range = (const PWR_CPU_FreqRange *)data;
            AppendStr(param, paramSize, &pos, "range=[%d,%d]MHz", range->minFreq, range->maxFreq);
            return;
        }
        case CPU_SET_DMA_LATENCY: {
            if (dataLen < sizeof(int)) {
                break;
            }
            AppendStr(param, paramSize, &pos, "latency=%d", *(const int *)data);
            return;
        }
        case SYS_SET_POWER_STATE: {
            if (dataLen < sizeof(int)) {
                break;
            }
            AppendStr(param, paramSize, &pos, "powerState=%d", *(const int *)data);
            return;
        }
        case HBM_SET_ALL_POWER_STATE:
        case PROC_SET_WATT_STATE:
        case PROC_SET_SMART_GRID_STATE: {
            if (dataLen < sizeof(int)) {
                break;
            }
            AppendStr(param, paramSize, &pos, "state=%s", StateToStr(*(const int *)data));
            return;
        }
        case PROC_SET_WATT_FIRST_DOMAIN: {
            if (dataLen < sizeof(int)) {
                break;
            }
            AppendStr(param, paramSize, &pos, "cpuId=%d", *(const int *)data);
            return;
        }
        case PROC_SET_WATT_ARRTS: {
            if (dataLen < sizeof(PWR_PROC_WattAttrs)) {
                break;
            }
            const PWR_PROC_WattAttrs *watt = (const PWR_PROC_WattAttrs *)data;
            AppendStr(param, paramSize, &pos, "threshold=%d interval=%d domainMask=%d",
                watt->scaleThreshold, watt->scaleInterval, watt->domainMask);
            return;
        }
        case PROC_ADD_WATT_PROCS:
        case PROC_DEL_WATT_PROCS: {
            if (dataLen % sizeof(pid_t) != 0) {
                break;
            }
            AppendPidList(param, paramSize, &pos, (const pid_t *)data, dataLen / sizeof(pid_t));
            return;
        }
        case PROC_SET_SMART_GRID_PROCS_LEVEL: {
            if (dataLen < sizeof(PWR_PROC_SmartGridProcs)) {
                break;
            }
            const PWR_PROC_SmartGridProcs *sg = (const PWR_PROC_SmartGridProcs *)data;
            uint32_t num = (uint32_t)((dataLen - sizeof(PWR_PROC_SmartGridProcs)) / sizeof(pid_t));
            if (sg->procNum >= 0 && (uint32_t)sg->procNum < num) {
                num = (uint32_t)sg->procNum;
            }
            AppendStr(param, paramSize, &pos, "level=%d procNum=%d ", sg->level, sg->procNum);
            AppendPidList(param, paramSize, &pos, sg->procs, num);
            return;
        }
        case PROC_SET_SMART_GRID_GOV: {
            if (dataLen < sizeof(PWR_PROC_SmartGridGov)) {
                break;
            }
            const PWR_PROC_SmartGridGov *gov = (const PWR_PROC_SmartGridGov *)data;
            char lv0[PWR_MAX_ELEMENT_NAME_LEN + 1] = {0};
            char lv1[PWR_MAX_ELEMENT_NAME_LEN + 1] = {0};
            CopyDataStr(lv0, sizeof(lv0), gov->sgLevel0Gov, sizeof(gov->sgLevel0Gov));
            CopyDataStr(lv1, sizeof(lv1), gov->sgLevel1Gov, sizeof(gov->sgLevel1Gov));
            AppendStr(param, paramSize, &pos, "agentState=%s level0Gov=\"%s\" level1Gov=\"%s\"",
                StateToStr(gov->sgAgentState), lv0, lv1);
            return;
        }
        case PROC_SET_SERVICE_STATE: {
            if (dataLen < sizeof(PWR_PROC_ServiceState)) {
                break;
            }
            const PWR_PROC_ServiceState *svc = (const PWR_PROC_ServiceState *)data;
            AppendStr(param, paramSize, &pos, "service=%d state=%d", (int)svc->name, svc->state);
            return;
        }
        default:
            break;
    }

    if (pos == 0) {
        AppendStr(param, paramSize, &pos, "dataLen=%u", dataLen);
    }
}

static int AuditBkpFilter(const struct dirent *item)
{
    if (item->d_type != DT_REG) {
        return 0;
    }
    return strncmp(item->d_name, AUDIT_BKP_PFX, strlen(AUDIT_BKP_PFX)) == 0;
}

/* Delete the oldest audit backups, keep at most AUDIT_MAX_BKP_CNT files. */
static void PruneAuditBackups(void)
{
    const char *dir = GetLogCfg()->logPath;
    struct dirent **fileList = NULL;
    int fileCnt = scandir(dir, &fileList, AuditBkpFilter, alphasort);
    if (fileCnt < 0) {
        return;
    }
    int delCnt = fileCnt - (int)AUDIT_MAX_BKP_CNT;
    for (int i = 0; i < fileCnt; i++) {
        if (i < delCnt) {
            char fullPath[MAX_FULL_NAME] = {0};
            if (snprintf(fullPath, sizeof(fullPath), "%s/%s", dir, fileList[i]->d_name) > 0) {
                (void)unlink(fullPath);
            }
        }
        free(fileList[i]);
    }
    free(fileList);
}

static FILE *OpenAuditFile(void)
{
    char fullName[MAX_FULL_NAME] = {0};
    if (snprintf(fullName, sizeof(fullName), "%s/%s", GetLogCfg()->logPath, AUDIT_FILE_NAME) < 0) {
        return NULL;
    }
    /* fopen("a") creates with 0666 & ~umask, so on hardened hosts
     * (umask 077) the file would land 0600 and non-root auditors could
     * not read it. Nail the manual-promised 0644 at creation time only:
     * reopens and any later admin chmod are left untouched. Rotation
     * lands here too (the renamed-over name no longer exists). */
    int created = (access(fullName, F_OK) != 0);
    FILE *fp = fopen(fullName, "a");
    if (fp == NULL) {
        return NULL;
    }
    if (created && fchmod(fileno(fp), AUDIT_FILE_MODE) != 0) {
        Logger(WARNING, MD_NM_LOG, "fchmod audit.log to 0644 failed");
    }
    struct stat st;
    g_auditSize = 0;
    if (stat(fullName, &st) == 0) {
        g_auditSize = (uint64_t)st.st_size;
    }
    return fp;
}

static int RotateAuditFile(void)
{
    char curTime[MAX_STD_TIME] = {0};
    char fullName[MAX_FULL_NAME] = {0};
    char bakName[MAX_FULL_NAME] = {0};

    if (g_auditFile != NULL) {
        fclose(g_auditFile);
        g_auditFile = NULL;
    }

    if (snprintf(fullName, sizeof(fullName), "%s/%s", GetLogCfg()->logPath, AUDIT_FILE_NAME) < 0) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    GetCurFmtTmStr("%Y%m%d%H%M%S", curTime, sizeof(curTime) - 1);
    if (snprintf(bakName, sizeof(bakName), "%s/%s%s", GetLogCfg()->logPath, AUDIT_BKP_PFX, curTime) < 0) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    (void)rename(fullName, bakName); // even if rename fails, reopen a fresh file
    PruneAuditBackups();
    g_auditFile = OpenAuditFile();
    return (g_auditFile != NULL) ? PWR_SUCCESS : PWR_ERR_SYS_EXCEPTION;
}

/* Emit one audit line. Self-heals by reopening the file when possible. */
static void EmitAuditLine(const char *line)
{
    pthread_mutex_lock(&g_auditLock);
    if (g_auditFile == NULL) {
        g_auditFile = OpenAuditFile();
        if (g_auditFile == NULL) {
            pthread_mutex_unlock(&g_auditLock);
            return;
        }
    }
    size_t len = strlen(line);
    if (fputs(line, g_auditFile) >= 0 && fputc('\n', g_auditFile) != EOF && fflush(g_auditFile) >= 0) {
        g_auditSize += len + 1;
        if (g_auditSize > AUDIT_MAX_FILE_SIZE) {
            (void)RotateAuditFile();
        }
    }
    pthread_mutex_unlock(&g_auditLock);
}

/* Caller identity helpers: client may be NULL (e.g. the client went away
 * between REQ and RSP); the identity is then recorded as "unknown" / "-",
 * the same degraded form the manual documents for WRITER[API]. */
static const char *ClientName(const PwrClient *client)
{
    return (client != NULL && client->userName[0] != '\0') ? client->userName : "unknown";
}

static unsigned int ClientUid(const PwrClient *client)
{
    return (client != NULL) ? (unsigned int)client->uid : (unsigned int)-1;
}

/* Display form of the client uid: a missing client prints as "-" instead of
 * leaking the (unsigned)-1 sentinel as 4294967295 into the log. */
static const char *ClientUidStr(const PwrClient *client, char *buf, size_t size)
{
    if (client != NULL) {
        snprintf(buf, size, "%u", (unsigned int)client->uid);
    } else {
        snprintf(buf, size, "-");
    }
    return buf;
}

static void ComposeCommonHead(char *line, size_t size, int *pos, const char *tag,
    const PwrClient *client, const PwrMsg *req)
{
    uint32_t sysId = (client != NULL) ? (uint32_t)client->sysId : req->head.sysId;

    char curTime[MAX_STD_TIME] = {0};
    GetCurFullTime(curTime, sizeof(curTime) - 1);
    char uidStr[16];
    AppendStr(line, size, pos, "%s [AUDIT][%s][API] user=%s uid=%s pid=%u opt=%s seq=%u",
        curTime, tag, ClientName(client), ClientUidStr(client, uidStr, sizeof(uidStr)),
        sysId, GetAuditOptName(req->head.optType), req->head.seqId);
}

int InitAuditLogger(void)
{
    const char *logPath = GetLogCfg()->logPath;
    if (access(logPath, F_OK) != 0) {
        if (MkDirs(logPath, AUDIT_DIR_MODE) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_LOG, "create audit log dir failed. path:%s", logPath);
            return PWR_ERR_SYS_EXCEPTION;
        }
    }
    pthread_mutex_lock(&g_auditLock);
    g_auditFile = OpenAuditFile();
    pthread_mutex_unlock(&g_auditLock);
    if (g_auditFile == NULL) {
        Logger(ERROR, MD_NM_LOG, "open audit log file failed. path:%s/%s", logPath, AUDIT_FILE_NAME);
        return PWR_ERR_COMMON;
    }
    return PWR_SUCCESS;
}

void ClearAuditLogger(void)
{
    /* Flush a pending aggregated WRITER run before the file is closed. */
    FlushAuditWriterPending();

    pthread_mutex_lock(&g_auditLock);
    if (g_auditFile != NULL) {
        fclose(g_auditFile);
        g_auditFile = NULL;
    }
    g_auditSize = 0;
    pthread_mutex_unlock(&g_auditLock);
}

void AuditClientConn(const PwrClient *client, enum AuditEvtType evt)
{
    const char *tag = (evt == AUDIT_EVT_CONN) ? "CONN" : "DISCONN";
    uint32_t sysId = (client != NULL) ? (uint32_t)client->sysId : 0;

    char line[AUDIT_MAX_LINE_LEN] = {0};
    int pos = 0;
    char curTime[MAX_STD_TIME] = {0};
    GetCurFullTime(curTime, sizeof(curTime) - 1);
    char uidStr[16];
    AppendStr(line, sizeof(line), &pos, "%s [AUDIT][%s][API] user=%s uid=%s pid=%u",
        curTime, tag, ClientName(client), ClientUidStr(client, uidStr, sizeof(uidStr)), sysId);
    EmitAuditLine(line);
}

void AuditSettingReq(const PwrClient *client, const PwrMsg *req)
{
    if (req == NULL || !IsAuditOpt(req->head.optType)) {
        return;
    }

    char param[AUDIT_MAX_PARAM_LEN] = {0};
    BuildParamStr(req->head.optType, req->data, req->head.dataLen, param, sizeof(param));

    char line[AUDIT_MAX_LINE_LEN] = {0};
    int pos = 0;
    ComposeCommonHead(line, sizeof(line), &pos, "REQ", client, req);
    AppendStr(line, sizeof(line), &pos, " param=\"%s\"", param);
    EmitAuditLine(line);

    /* Register the call so WRITER events can correlate against it. */
    pthread_mutex_lock(&g_callLock);
    struct InflightCall *slot = AcquireCallSlot();
    if (slot != NULL) {
        slot->used = 1;
        slot->hasTid = 0;
        slot->tid = -1;
        slot->seq = req->head.seqId;
        slot->optType = req->head.optType;
        slot->uid = (uid_t)ClientUid(client);
        SetStr(slot->user, sizeof(slot->user), ClientName(client));
        slot->startMs = NowMs();
        slot->endMs = 0;
    }
    pthread_mutex_unlock(&g_callLock);
}

void AuditSettingRsp(const PwrClient *client, const PwrMsg *req, int rspCode)
{
    if (req == NULL || !IsAuditOpt(req->head.optType)) {
        return;
    }

    /* Emit a pending aggregated WRITER run first, so the audit file reads
     * "the writes happened, then the call responded". */
    FlushAuditWriterPending();

    char line[AUDIT_MAX_LINE_LEN] = {0};
    int pos = 0;
    ComposeCommonHead(line, sizeof(line), &pos, "RSP", client, req);
    AppendStr(line, sizeof(line), &pos, " result=%s rspCode=%d",
        (rspCode == PWR_SUCCESS) ? "success" : "failed", rspCode);
    EmitAuditLine(line);

    pthread_mutex_lock(&g_callLock);
    struct InflightCall *slot = FindCall(req->head.seqId, req->head.optType);
    if (slot != NULL && slot->endMs == 0) {
        /* Keep the registration (and the thread binding) for the grace
         * window: the call's writes are typically drained from the BPF
         * rings after the response is out. */
        slot->endMs = NowMs();
    }
    pthread_mutex_unlock(&g_callLock);
}

void AuditCallBegin(const PwrMsg *req)
{
    if (req == NULL || !IsAuditOpt(req->head.optType)) {
        return;
    }
    pid_t tid = (pid_t)syscall(SYS_gettid);
    pthread_mutex_lock(&g_callLock);
    struct InflightCall *slot = FindCall(req->head.seqId, req->head.optType);
    if (slot != NULL) {
        slot->tid = tid;
        slot->hasTid = 1;
    }
    pthread_mutex_unlock(&g_callLock);
}

void AuditCallEnd(void)
{
    /* Stamp the finish time but keep the thread binding: writes issued by
     * this thread during the call reach user space through the perf ring
     * and are drained up to one collector poll (50ms) AFTER this point.
     * The slot expires via AUDIT_CALL_GRACE_MS. */
    pid_t tid = (pid_t)syscall(SYS_gettid);
    long long now = NowMs();
    pthread_mutex_lock(&g_callLock);
    for (int i = 0; i < AUDIT_MAX_INFLIGHT; i++) {
        if (g_calls[i].used && g_calls[i].hasTid && g_calls[i].tid == tid &&
            g_calls[i].endMs == 0) {
            g_calls[i].endMs = now;
        }
    }
    pthread_mutex_unlock(&g_callLock);
}

/* Resolve the API-call context of a WRITER event emitted by the service
 * itself: match the captured thread id while the call is in flight, or
 * within the grace window after it finished (the collector drains the
 * perf rings on a 50ms poll, long after a fast call completed). Returns
 * 0 when no call context applies - the event is then logged without
 * opt/seq/user rather than guessed. Caller provides buffers. */
static int FindWriterCall(pid_t tid, uint16_t *optType, uint32_t *seq,
    uid_t *uid, char *user, size_t userSize)
{
    struct InflightCall *match = NULL;
    long long now = NowMs();
    pthread_mutex_lock(&g_callLock);
    /* Pass 1: a call currently executing on this thread. */
    for (int i = 0; i < AUDIT_MAX_INFLIGHT; i++) {
        if (g_calls[i].used && g_calls[i].hasTid && g_calls[i].tid == tid &&
            g_calls[i].endMs == 0) {
            match = &g_calls[i];
            break;
        }
    }
    /* Pass 2: a call that finished on this thread within the grace
     * window (most recent wins if several are still lingering). */
    if (match == NULL) {
        long long best = 0;
        for (int i = 0; i < AUDIT_MAX_INFLIGHT; i++) {
            if (g_calls[i].used && g_calls[i].hasTid && g_calls[i].tid == tid &&
                g_calls[i].endMs != 0 &&
                now - g_calls[i].endMs < AUDIT_CALL_GRACE_MS &&
                g_calls[i].endMs > best) {
                best = g_calls[i].endMs;
                match = &g_calls[i];
            }
        }
    }
    if (match != NULL) {
        *optType = match->optType;
        *seq = match->seq;
        *uid = match->uid;
        snprintf(user, userSize, "%s", match->user);
    }
    pthread_mutex_unlock(&g_callLock);
    return (match != NULL);
}

/* ---- WRITER fan-out aggregation (compact mode) ---------------------------
 * One SetFreqGovernor call fans out to ~600 sibling sysfs writes on a
 * 608-CPU machine (one per policy dir). In compact mode
 * (bpf_writer_compact, default on) runs of sibling writes that share the
 * same identity and differ only in the path component before the file name
 * are collapsed into ONE line:
 *   file_glob="/sys/.../cpufreq/STAR/scaling_governor" count=600 first=.. last=..
 * A run whose events all wrote the exact same path keeps the exact
 *   file="/var/tmp/watchfile" count=N first=.. last=..
 * form instead - the star would over-claim directories never written.
 * The pending run is emitted when a non-matching event arrives, before an
 * RSP line, on a collector tick without new events, and at shutdown.
 * count=1 runs keep the original file= form, so nothing is lost for
 * single writes. Lock order is always wAggrLock -> auditLock. */
struct WriterAggr {
    int used;
    int isApi;          /* [WRITER][API] run: the service's own writes */
    int hasCall;        /* API: call context resolved */
    uint16_t optType;
    uint32_t seq;
    unsigned int uid;   /* API: caller uid; OS: writer uid */
    pid_t pid;          /* API: service pid; OS: writer pid */
    char user[MAX_NAME];
    char userName[64];
    char comm[32];                  /* escaped */
    char exe[AUDIT_MAX_LINE_LEN];   /* escaped, "-" when unavailable */
    char cmd[AUDIT_MAX_LINE_LEN];   /* escaped, "-" when unavailable */
    char file[AUDIT_MAX_LINE_LEN];  /* first event's real path, escaped */
    char globPath[AUDIT_MAX_LINE_LEN]; /* glob form of the path, escaped */
    int samePath;       /* every event in the run wrote the exact same path */
    char value[AUDIT_MAX_LINE_LEN];    /* escaped */
    char tsFirst[MAX_STD_TIME];
    char tsLast[MAX_STD_TIME];
    unsigned int count;
};
static struct WriterAggr g_wAggr;
static int g_wAggrTouched; /* events arrived since the last tick flush */
static pthread_mutex_t g_wAggrLock = PTHREAD_MUTEX_INITIALIZER;

/* Collapse the second-to-last path component into "*": the per-policy or
 * per-device directory that fans out on big machines, e.g.
 * /sys/devices/system/cpu/cpufreq/policy200/scaling_governor becomes
 * /sys/devices/system/cpu/cpufreq/STAR/scaling_governor. Paths without a
 * distinct directory component (e.g. "/file") are kept as-is. */
static void NormalizeGlobPath(const char *path, char *out, size_t outSize)
{
    const char *lastSlash = strrchr(path, '/');
    if (lastSlash == NULL) {
        snprintf(out, outSize, "%s", path);
        return;
    }
    const char *prev = NULL;
    for (const char *p = path; p < lastSlash; p++) {
        if (*p == '/') {
            prev = p;
        }
    }
    if (prev == NULL || prev == path) {
        /* "/file": the second-to-last component is the parent itself. */
        snprintf(out, outSize, "%s", path);
        return;
    }
    snprintf(out, outSize, "%.*s*%s", (int)(prev - path + 1), path, lastSlash);
}

/* Emit the pending run (if any) and reset the slot. Caller holds
 * g_wAggrLock; EmitAuditLine takes g_auditLock inside. */
static void FlushWriterAggrLocked(void)
{
    if (!g_wAggr.used) {
        return;
    }
    /* Runs whose events all wrote the exact same path keep the precise
     * file= form (a glob with a star would claim writes to directories
     * that never happened); only genuinely differing sibling directories
     * collapse into the file_glob= form. */
    const char *fileKey = (g_wAggr.count > 1 && !g_wAggr.samePath) ? "file_glob" : "file";
    const char *fileVal = (g_wAggr.count > 1 && !g_wAggr.samePath) ? g_wAggr.globPath : g_wAggr.file;

    char agg[AUDIT_MAX_LINE_LEN] = {0};
    int aggPos = 0;
    if (g_wAggr.count > 1) {
        AppendStr(agg, sizeof(agg), &aggPos, " count=%u first=\"%s\" last=\"%s\"",
            g_wAggr.count, g_wAggr.tsFirst, g_wAggr.tsLast);
    }

    char line[AUDIT_MAX_LINE_LEN] = {0};
    int pos = 0;
    if (g_wAggr.isApi) {
        AppendStr(line, sizeof(line), &pos, "%s [AUDIT][WRITER][API] ", g_wAggr.tsFirst);
        if (g_wAggr.hasCall) {
            AppendStr(line, sizeof(line), &pos, "user=%s uid=%u opt=%s seq=%u",
                g_wAggr.user, g_wAggr.uid,
                GetAuditOptName(g_wAggr.optType), g_wAggr.seq);
        } else {
            AppendStr(line, sizeof(line), &pos, "user=- uid=- opt=- seq=-");
        }
        AppendStr(line, sizeof(line), &pos, " pid=%d comm=\"%s\" %s=\"%s\"%s value=\"%s\"",
            g_wAggr.pid, g_wAggr.comm, fileKey, fileVal, agg, g_wAggr.value);
    } else {
        /* An ESC byte in the value is the typical signature of a
         * terminal-title write caught by a dup2(2) fd race. */
        const char *suspect = (strstr(g_wAggr.value, "\\x1b") != NULL) ? "esc" : "0";
        AppendStr(line, sizeof(line), &pos,
            "%s [AUDIT][WRITER][OS] uid=%u pid=%d user=%s comm=\"%s\" exe=\"%s\" cmd=\"%s\" %s=\"%s\"%s value=\"%s\" attr=late suspect=%s",
            g_wAggr.tsFirst, g_wAggr.uid, g_wAggr.pid, g_wAggr.userName,
            g_wAggr.comm, g_wAggr.exe, g_wAggr.cmd,
            fileKey, fileVal, agg, g_wAggr.value, suspect);
    }
    EmitAuditLine(line);
    memset(&g_wAggr, 0, sizeof(g_wAggr));
}

void FlushAuditWriterPending(void)
{
    pthread_mutex_lock(&g_wAggrLock);
    FlushWriterAggrLocked();
    pthread_mutex_unlock(&g_wAggrLock);
}

void AuditWriterTickFlush(void)
{
    pthread_mutex_lock(&g_wAggrLock);
    if (!g_wAggrTouched) {
        /* No new events in this drain pass: the run has settled. */
        FlushWriterAggrLocked();
    }
    g_wAggrTouched = 0;
    pthread_mutex_unlock(&g_wAggrLock);
}

void AuditWriterEvent(const struct WriterAudit *wa)
{
    if (wa == NULL || wa->file == NULL) {
        return;
    }
    char curTime[MAX_STD_TIME] = {0};
    const char *ts = wa->ts;
    if (ts == NULL || ts[0] == '\0') {
        GetCurFullTime(curTime, sizeof(curTime) - 1);
        ts = curTime;
    }

    char sComm[32] = {0};
    char sFile[AUDIT_MAX_LINE_LEN] = {0};
    char sValue[AUDIT_MAX_LINE_LEN] = {0};
    char sExe[AUDIT_MAX_LINE_LEN] = {0};
    char sCmd[AUDIT_MAX_LINE_LEN] = {0};
    char sUserName[64] = {0};
    EscField(sComm, sizeof(sComm), wa->comm);
    EscField(sFile, sizeof(sFile), wa->file);
    EscField(sValue, sizeof(sValue), wa->value);
    EscField(sExe, sizeof(sExe), wa->exe);
    EscField(sCmd, sizeof(sCmd), wa->cmd);
    EscField(sUserName, sizeof(sUserName), wa->userName);

    int isApi = (wa->pid == (int)getpid());
    /* Resolve the API context first: the pending run needs it, and it must
     * be read before the call's grace window expires. */
    uint16_t optType = 0;
    uint32_t seq = 0;
    uid_t callerUid = (uid_t)-1;
    char callerUser[MAX_NAME] = {0};
    int hasCall = 0;
    if (isApi) {
        hasCall = FindWriterCall(wa->tid, &optType, &seq, &callerUid,
            callerUser, sizeof(callerUser));
    }

    char globRaw[AUDIT_MAX_LINE_LEN] = {0};
    char sGlob[AUDIT_MAX_LINE_LEN] = {0};
    NormalizeGlobPath(wa->file, globRaw, sizeof(globRaw));
    EscField(sGlob, sizeof(sGlob), globRaw);

    int compact = (GetBpfCfg()->compact != 0);

    pthread_mutex_lock(&g_wAggrLock);
    int matched = g_wAggr.used && compact &&
        g_wAggr.isApi == isApi &&
        g_wAggr.pid == wa->pid &&
        strcmp(g_wAggr.globPath, sGlob) == 0 &&
        strcmp(g_wAggr.value, sValue) == 0;
    if (matched && isApi) {
        matched = (g_wAggr.hasCall == hasCall) && (!hasCall ||
            (g_wAggr.optType == optType && g_wAggr.seq == seq &&
             strcmp(g_wAggr.user, callerUser) == 0));
    }
    if (matched && !isApi) {
        matched = g_wAggr.uid == wa->uid && strcmp(g_wAggr.comm, sComm) == 0 &&
            strcmp(g_wAggr.exe, sExe) == 0 && strcmp(g_wAggr.cmd, sCmd) == 0;
    }

    if (matched) {
        g_wAggr.count++;
        if (strcmp(g_wAggr.file, sFile) != 0) {
            g_wAggr.samePath = 0; /* a sibling wrote a different directory */
        }
        SetStr(g_wAggr.tsLast, sizeof(g_wAggr.tsLast), ts);
        g_wAggrTouched = 1;
        pthread_mutex_unlock(&g_wAggrLock);
        return;
    }

    /* Key change (or compact off): emit the previous run, start a new one. */
    FlushWriterAggrLocked();

    struct WriterAggr *a = &g_wAggr;
    memset(a, 0, sizeof(*a));
    a->used = 1;
    a->isApi = isApi;
    a->hasCall = hasCall;
    a->optType = optType;
    a->seq = seq;
    a->pid = wa->pid;
    if (isApi) {
        a->uid = (unsigned)callerUid;
        SetStr(a->user, sizeof(a->user), (callerUser[0] != '\0') ? callerUser : "unknown");
    } else {
        a->uid = wa->uid;
        SetStr(a->userName, sizeof(a->userName), (sUserName[0] != '\0') ? sUserName : "unknown");
        SetStr(a->exe, sizeof(a->exe), (sExe[0] != '\0') ? sExe : "-");
        SetStr(a->cmd, sizeof(a->cmd), (sCmd[0] != '\0') ? sCmd : "-");
    }
    SetStr(a->comm, sizeof(a->comm), sComm);
    SetStr(a->file, sizeof(a->file), sFile);
    SetStr(a->globPath, sizeof(a->globPath), sGlob);
    a->samePath = 1;
    SetStr(a->value, sizeof(a->value), sValue);
    SetStr(a->tsFirst, sizeof(a->tsFirst), ts);
    SetStr(a->tsLast, sizeof(a->tsLast), ts);
    a->count = 1;
    g_wAggrTouched = 1;

    if (!compact) {
        /* Compact disabled: every write stays its own line. */
        FlushWriterAggrLocked();
    }
    pthread_mutex_unlock(&g_wAggrLock);
}
