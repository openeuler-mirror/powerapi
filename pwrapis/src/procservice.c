/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: queyanwen
 * Create: 2023-10-19
 * Description: provide cpu service
 * **************************************************************************** */

#include "procservice.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "utils.h"
#include "cpuservice.h"

#define GET_US_PROCS_CMD "ps -ef | grep -v '\\[' | awk 'NR > 1 {print $2}'"
#define QUERY_PROCS_CMD "ps -ef | grep -E '%s' | grep -v grep | awk '{print $2}'"

#define WATT_CGROUP_PATH "/sys/fs/cgroup/cpu/watt_sched"
#define WATT_STATE_PATH "/sys/fs/cgroup/cpu/watt_sched/cpu.dynamic_affinity_mode"
#define WATT_ATTR_SCALE_THRESHOLD_PATH  "/proc/sys/kernel/sched_util_low_pct"
#define WATT_ATTR_DOMAIN_MASK_PATH      "/sys/fs/cgroup/cpu/watt_sched/cpu.affinity_domain_mask"
#define WATT_ATTR_SCALE_INTERVAL_PATH   "/sys/fs/cgroup/cpu/watt_sched/cpu.affinity_period_ms"
#define WATT_PROC_PATH                  "/sys/fs/cgroup/cpu/watt_sched/tasks"
#define WATT_REBUILD_AFFINITY_DOMAIN_PATH "/sys/fs/cgroup/cpu/watt_sched/cpu.rebuild_affinity_domain"
#define ROOT_CGROUP_PROC_PATH           "/sys/fs/cgroup/cpu/tasks"
#define ROOT_CGOUP_WATT_PATH            "/sys/fs/cgroup/cpu/cpu.dynamic_affinity_mode"
#define ROOT_CGROUP_WATT_SET_DOMAIN_PATH "/sys/fs/cgroup/cpu/cpu.rebuild_affinity_domain"

#define SMART_GRID_STATE_PATH "/proc/sys/kernel/smart_grid_strategy_ctrl"
#define SMART_GRID_LEVEL_PATH_D "/proc/%d/smart_grid_level"
#define SMART_GRID_LEVEL_PATH_S "/proc/%s/smart_grid_level"
#define PROC_PATH "/proc"
#define SMART_GRID_GOV_ENABL_PATH "/sys/devices/system/cpu/cpufreq/smart_grid_governor_enable"
#define SMART_GRID_GOV_PATH "/sys/devices/system/cpu/cpufreq/smart_grid_governor"
#define SERVICE_PATH "/usr/lib/systemd/system/%s.service"
#define QUERY_SERVICE_STATE_CMD "systemctl status %s | grep -o 'Active:.*' | awk '{print $2, $3}'"
#define MODIFY_SERVICE_STATE_CMD "systemctl %s %s"

#define CHECK_SUPPORT_WATT_SCHED()                                              \
    {                                                                           \
        if (access(ROOT_CGOUP_WATT_PATH, F_OK) != 0) {                          \
            SendRspToClient(req, PWR_ERR_WATT_SCHED_NOT_SURPPORTED, NULL, 0);   \
            return;                                                             \
        }                                                                       \
    }

#define CHECK_WATT_SCHED_EXIST()                                                \
    {                                                                           \
        if (access(WATT_PROC_PATH, F_OK) != 0) {                                \
            SendRspToClient(req, PWR_ERR_WATT_SCHED_NEVER_ENABLED, NULL, 0);    \
            return;                                                             \
        }                                                                       \
    }

#define CHECK_SUPPORT_SMART_GRID()                                              \
    {                                                                           \
        if (access(SMART_GRID_STATE_PATH, F_OK) != 0) {                         \
            SendRspToClient(req, PWR_ERR_SMART_GRID_NOT_SURPPORTED, NULL, 0);   \
            return;                                                             \
        }                                                                       \
    }

static ServiceToString g_serToString[] = {
    {PWR_PROC_SERVICE_EAGLE, "eagle"},
    {PWR_PROC_SERVICE_MPCTOOL, "mpctool"},
};

static int CheckServiceExist(const PWR_PROC_SERVICE_NAME name, char *serviceName)
{
    int i;
    int count = sizeof(g_serToString) / sizeof(g_serToString[0]);
    char servicePath[MAX_PATH_NAME] = {0};
    for (i = 0; i < count; i++) {
        if (name == g_serToString[i].name) {
            StrCopy(serviceName, g_serToString[i].nameString, MAX_SERVICE_LEN);
            break;
        }
    }
    if (i == count) {
        return PWR_ERR_SERVICE_UNABLE;
    }
    if (snprintf(servicePath, sizeof(servicePath), SERVICE_PATH, g_serToString[i].nameString) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }
    if (access(servicePath, F_OK) != 0) {
        return PWR_ERR_SERVICE_NOT_EXIST;
    }
    return PWR_SUCCESS;
}

static int ReadServiceState(PWR_PROC_ServiceStatus *sStatus, const char *serviceName)
{
    char cmd[PWR_MAX_STRING_LEN] = {0};
    char buf[PWR_MAX_STRING_LEN] = {0};

    if (sprintf(cmd, QUERY_SERVICE_STATE_CMD, serviceName) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return PWR_ERR_SYS_EXCEPTION;
    }

    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        pclose(fp);
        return PWR_ERR_COMMON;
    }
    DeleteChar(buf, '\n');

    if (strcmp(buf, "inactive (dead)") == 0) {
        sStatus->status = PWR_PROC_SRV_ST_INACTIVE;
    } else if (strcmp(buf, "activating (auto-restart)") == 0) {
        sStatus->status = PWR_PROC_SRV_ST_ACTIVATING;
    } else if (strcmp(buf, "active (running)") == 0) {
        sStatus->status = PWR_PROC_SRV_ST_RUNNING;
    } else if (strcmp(buf, "active (exited)") == 0) {
        sStatus->status = PWR_PROC_SRV_ST_EXITED;
    } else if (strcmp(buf, "active (waiting)") == 0) {
        sStatus->status = PWR_PROC_SRV_ST_WAITING;
    } else if (strstr(buf, "failed") != NULL) {
        sStatus->status = PWR_PROC_SRV_ST_FAILED;
    } else {
        sStatus->status = PWR_PROC_SRV_ST_UNKNOWN;
    }

    pclose(fp);
    return PWR_SUCCESS;
}

static int ModifyServiceState(const PWR_PROC_ServiceState *sState, const char *serviceName)
{
    char cmd[PWR_MAX_STRING_LEN] = {0};
    char oper[PWR_MAX_NAME_LEN] = {0};
    if (sState->state == PWR_SERVICE_START){
        StrCopy(oper, "start", PWR_MAX_NAME_LEN);
    } else {
        StrCopy(oper, "stop", PWR_MAX_NAME_LEN);
    }

    if (sprintf(cmd, MODIFY_SERVICE_STATE_CMD, oper, serviceName) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    pclose(fp);
    return PWR_SUCCESS;
}

static int QueryProcs(const char *keyWords, pid_t procs[], int maxNum, int *procNum)
{
    char cmd[PWR_MAX_STRING_LEN + sizeof(QUERY_PROCS_CMD)] = GET_US_PROCS_CMD;
    if (keyWords && strlen(keyWords) != 0) {
        if (sprintf(cmd, QUERY_PROCS_CMD, keyWords) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
    }
    Logger(DEBUG, MD_NM_SVR_PROC, "QueryProcs: %s", cmd);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    char line[STR_LEN_FOR_INT] = {0};
    *procNum = 0;
    while (fgets(line, STR_LEN_FOR_INT - 1, fp) != NULL && *procNum < maxNum) {
        procs[*procNum] = atoi(line);
        (*procNum)++;
    }
    pclose(fp);
    if (*procNum == 0) {
        return PWR_ERR_NO_PROCS_BY_KEYWORD;
    }
    return PWR_SUCCESS;
}

static inline int ReadWattState(int *state)
{
    char buff[PWR_STATE_LEN] = {0};

    // already check whether watt scheduler is supported
    if (access(WATT_CGROUP_PATH, F_OK) != 0 && MkDirs(WATT_CGROUP_PATH, CRT_DIR_MODE) != PWR_SUCCESS) {
        return PWR_ERR_SYS_EXCEPTION;
    }

    int ret = ReadFile(WATT_STATE_PATH, buff, PWR_STATE_LEN);
    if (ret == PWR_SUCCESS) {
        *state = atoi(buff);
    }
    return ret;
}

static int ReadWattAttrs(PWR_PROC_WattAttrs *wattAttrs)
{
    char buff[STR_LEN_FOR_INT] = {0};
    int ret = ReadFile(WATT_ATTR_SCALE_THRESHOLD_PATH, buff, STR_LEN_FOR_INT);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    wattAttrs->scaleThreshold = atoi(buff);
    memset(buff, 0, sizeof(buff));
    ret = ReadFile(WATT_ATTR_DOMAIN_MASK_PATH, buff, STR_LEN_FOR_INT);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    wattAttrs->domainMask = atoi(buff);
    memset(buff, 0, sizeof(buff));
    ret = ReadFile(WATT_ATTR_SCALE_INTERVAL_PATH, buff, STR_LEN_FOR_INT);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    wattAttrs->scaleInterval = atoi(buff);
    return PWR_SUCCESS;
}

static int WriteWattAttrs(const PWR_PROC_WattAttrs *wattAttrs)
{
    int ret = PWR_SUCCESS;
    if (wattAttrs->scaleThreshold != 0) {
        ret = WriteIntToFile(WATT_ATTR_SCALE_THRESHOLD_PATH, wattAttrs->scaleThreshold);
        if (ret != PWR_SUCCESS) {
            return ret;
        }
    }
    if (wattAttrs->domainMask != 0) {
        ret = WriteIntToFile(WATT_ATTR_DOMAIN_MASK_PATH, wattAttrs->domainMask);
        if (ret != PWR_SUCCESS) {
            return ret;
        }
    }
    if (wattAttrs->scaleInterval != 0) {
        ret = WriteIntToFile(WATT_ATTR_SCALE_INTERVAL_PATH, wattAttrs->scaleInterval);
        if (ret != PWR_SUCCESS) {
            return ret;
        }
    }
    return PWR_SUCCESS;
}

static int ReadWattProcs(pid_t *wattProcs, int len, int *procNum)
{
    FILE *fp = fopen(WATT_PROC_PATH, "r");
    if (fp == NULL) {
        Logger(ERROR, MD_NM_SVR_PROC, "Failed to open file %s. errno:%d, %s", WATT_PROC_PATH, errno, strerror(errno));
        return PWR_ERR_FILE_OPEN_FAILED;
    }

    char line[PWR_MAX_STRING_LEN] = {0};
    int idx = 0;
    while (fgets(line, PWR_MAX_STRING_LEN - 1, fp) != NULL && idx < len) {
        LRtrim(line);
        wattProcs[idx] = (pid_t)atoi(line);
        idx++;
    }

    *procNum = idx;

    return PWR_SUCCESS;
}

static int ReadSmartGridProcsByLevel(PWR_PROC_SMART_GRID_LEVEL level,
    PWR_PROC_SmartGridProcs *sgProcs, int maxNum)
{
    DIR *dir = opendir(PROC_PATH);
    if (!dir) {
        Logger(ERROR, MD_NM_SVR_PROC, "Unable to open direct: %s", PROC_PATH);
        return PWR_ERR_FILE_OPEN_FAILED;
    }
    struct dirent *dt;
    char procLevelPath[MAX_FULL_NAME] = {0};
    char strLevel[STR_LEN_FOR_INT] = {0};
    StrCopy(procLevelPath, PROC_PATH, MAX_FULL_NAME);
    while ((dt = readdir(dir)) != NULL && sgProcs->procNum < maxNum) {
        if (!IsNumStr(dt->d_name)) {
            continue;
        }
        if (sprintf(procLevelPath, SMART_GRID_LEVEL_PATH_S, dt->d_name) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        if (ReadFile(procLevelPath, strLevel, STR_LEN_FOR_INT) != PWR_SUCCESS) {
            continue;
        }
        if (atoi(strLevel) == (int)level) {
            sgProcs->procs[sgProcs->procNum] = (pid_t)atoi(dt->d_name);
            sgProcs->procNum++;
        }
    }
    return PWR_SUCCESS;
}

static int WriteSmartGridProcsLevel(const PWR_PROC_SmartGridProcs *sgProcs)
{
    char strLevel[STR_LEN_FOR_INT] = {0};
    if (sprintf(strLevel, "%d", sgProcs->level) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }
    char procLevelPath[MAX_FULL_NAME] = {0};
    for (int i = 0; i < sgProcs->procNum; i++) {
        if (sprintf(procLevelPath, SMART_GRID_LEVEL_PATH_D, sgProcs->procs[i]) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        (void)WriteFile(procLevelPath, strLevel, strlen(strLevel));
    }
    return PWR_SUCCESS;
}

static int SmartGridGovEnabled()
{
    if (access(SMART_GRID_GOV_ENABL_PATH, F_OK) != 0) {
        return PWR_FALSE;
    }

    char buff[PWR_STATE_LEN] = {0};
    int ret = ReadFile(SMART_GRID_GOV_ENABL_PATH, buff, PWR_STATE_LEN);
    if (ret != PWR_SUCCESS) {
        return PWR_FALSE;
    }
    int state = atoi(buff);
    return (state == PWR_ENABLE);
}

#define LEVEL0_PREFIX "smart_grid-0: "
#define LEVEL1_PREFIX "smart_grid-1: "
static int ReadSmartGridGov(PWR_PROC_SmartGridGov *sgGov)
{
    if (!SmartGridGovEnabled()) {
        bzero(sgGov, sizeof(PWR_PROC_SmartGridGov));
        sgGov->sgAgentState = PWR_DISABLE;
        return PWR_SUCCESS;
    }
    sgGov->sgAgentState = PWR_ENABLE;

    FILE *fp = fopen(SMART_GRID_GOV_PATH, "r");
    if (fp == NULL) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    char line[PWR_MAX_STRING_LEN] = {0};
    while (fgets(line, PWR_MAX_STRING_LEN - 1, fp) != NULL) {
        LRtrim(line);
        if (strstr(line, LEVEL0_PREFIX) != NULL) {
            DeleteSubstr(line, LEVEL0_PREFIX);
            Ltrim(line);
            StrCopy(sgGov->sgLevel0Gov, line, PWR_MAX_ELEMENT_NAME_LEN);
            continue;
        }
        if (strstr(line, LEVEL1_PREFIX) != NULL) {
            DeleteSubstr(line, LEVEL1_PREFIX);
            Ltrim(line);
            StrCopy(sgGov->sgLevel1Gov, line, PWR_MAX_ELEMENT_NAME_LEN);
            continue;
        }
    }
    fclose(fp);
    return PWR_SUCCESS;
}

static inline int DisableSmartGridGov()
{
    return WriteIntToFile(SMART_GRID_GOV_ENABL_PATH, 0);
}

static inline int EnableSmartGridGov()
{
    return WriteIntToFile(SMART_GRID_GOV_ENABL_PATH, 1);
}

#define EXT_GOV_NAME_LEN (PWR_MAX_ELEMENT_NAME_LEN + 2)
static int WriteSmartGridGov(PWR_PROC_SmartGridGov *sgGov)
{
    if (sgGov->sgAgentState == PWR_DISABLE) {
        if (!SmartGridGovEnabled()) {
            return PWR_SUCCESS;
        }
        return DisableSmartGridGov();
    }
    // sgGov->sgAgentState == PWR_ENABLE
    if (!SmartGridGovEnabled()) {
        int ret = EnableSmartGridGov();
        if (ret != PWR_SUCCESS) {
            return ret;
        }
    }

    char gov[EXT_GOV_NAME_LEN] = {0};
    if (strlen(sgGov->sgLevel0Gov) != 0) {
        if (sprintf(gov, "0-%s", sgGov->sgLevel0Gov) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        int ret = WriteFile(SMART_GRID_GOV_PATH, gov, strlen(gov));
        if (ret != PWR_SUCCESS) {
            return ret;
        }
    }

    if (strlen(sgGov->sgLevel1Gov) != 0) {
        if (sprintf(gov, "1-%s", sgGov->sgLevel1Gov) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        return WriteFile(SMART_GRID_GOV_PATH, gov, strlen(gov));
    }
    return PWR_SUCCESS;
}

// public===========================================================================================
void ProcQueryProcs(PwrMsg *req)
{
    char *keyWords = NULL;
    if (req->head.dataLen != 0 && req->data && strlen(req->data) != 0) {
        keyWords = req->data;
    }

    size_t size = sizeof(pid_t) * PWR_MAX_PROC_NUM;
    pid_t *procs = (pid_t *)malloc(size);
    if (!procs) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(procs, size);
    int procNum = 0;
    int rspCode = QueryProcs(keyWords, procs, PWR_MAX_PROC_NUM, &procNum);
    if (rspCode != PWR_SUCCESS) {
        free(procs);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)procs, procNum * sizeof(pid_t));
    }
}

void ProcGetWattState(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    int *state = (int *)malloc(sizeof(int));
    if (!state) {
        return;
    }
    *state = PWR_DISABLE;
    (void)ReadWattState(state);
    SendRspToClient(req, PWR_SUCCESS, (char *)state, sizeof(int));
}

void ProcSetWattState(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    if (req->head.dataLen != sizeof(int) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    int *state = (int *)req->data;
    if (*state != PWR_ENABLE && *state != PWR_DISABLE) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    if (access(WATT_CGROUP_PATH, F_OK) != 0 && MkDirs(WATT_CGROUP_PATH, CRT_DIR_MODE) != PWR_SUCCESS) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    int rspCode = WriteIntToFile(WATT_STATE_PATH, *state);
    SendRspToClient(req, rspCode, NULL, 0);
}

#define CPUINFO_FILE "/sys/devices/system/cpu/cpu%d/online"
static int checkIfCpuOnline(int cpuId)
{
    char fileName[MAX_FULL_NAME];

    snprintf(fileName, sizeof(fileName), CPUINFO_FILE, cpuId);

     // CPU0 is always online on some systems.
    if (cpuId == 0 && access(fileName, F_OK) != 0) {
        return PWR_TRUE;
    }

    int isOnline = PWR_FALSE;
    if (ReadIntFromFile(fileName, &isOnline) != PWR_SUCCESS) {
        return PWR_FALSE;
    }
    return isOnline;
}

void ProcSetWattFirstDomain(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    if (req->head.dataLen != sizeof(int) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }

    int *cpuId = (int *)req->data;
    if (*cpuId < 0 || GetCpuCoreNumber() <= *cpuId || !checkIfCpuOnline(*cpuId)) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }

    if (access(ROOT_CGROUP_WATT_SET_DOMAIN_PATH, F_OK) != 0) {
        SendRspToClient(req, PWR_ERR_WATT_NOT_SUPPORT_SET_DOMAIN, NULL, 0);
        return;
    }

    int state = PWR_DISABLE;
    int ret = ReadWattState(&state);
    if (state == PWR_ENABLE) { // could set watt first domain only when watt is disabled
        return SendRspToClient(req, PWR_ERR_WATT_NEED_DISABLE_TO_SET_DOMAIN, NULL, 0);
    }

    ret = WriteIntToFile(WATT_REBUILD_AFFINITY_DOMAIN_PATH, *cpuId);
    SendRspToClient(req, ret, NULL, 0);
}

void procGetWattAttrs(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    CHECK_WATT_SCHED_EXIST();
    size_t size = sizeof(PWR_PROC_WattAttrs);
    PWR_PROC_WattAttrs *wattAttrs = (PWR_PROC_WattAttrs *)malloc(size);
    if (!wattAttrs) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(wattAttrs, size);
    int rspCode = ReadWattAttrs(wattAttrs);
    if (rspCode != PWR_SUCCESS) {
        free(wattAttrs);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)wattAttrs, size);
    }
}

void ProcSetWattAttrs(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    CHECK_WATT_SCHED_EXIST();
    if (req->head.dataLen != sizeof(PWR_PROC_WattAttrs) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    PWR_PROC_WattAttrs *wattAttrs = (PWR_PROC_WattAttrs *)req->data;
    if (wattAttrs->scaleThreshold < 0 || wattAttrs->scaleThreshold > PWR_ONE_HUNDRED
        || wattAttrs->scaleInterval <0 || wattAttrs->scaleInterval > PWR_MAX_WATT_SCALE_INTERVAL
        || wattAttrs->domainMask < 0) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    // Record the original data so that it can be restored to the
    // previous value if some settings fails.
    PWR_PROC_WattAttrs orgAttrs = {0};
    if (ReadWattAttrs(&orgAttrs) != PWR_SUCCESS) {
        SendRspToClient(req, PWR_ERR_WATT_SCHED_NEVER_ENABLED, NULL, 0);
        return;
    }
    int rspCode = WriteWattAttrs(wattAttrs);
    if (rspCode != PWR_SUCCESS) {
        WriteWattAttrs(&orgAttrs);
    }
    SendRspToClient(req, rspCode, NULL, 0);
}

void ProcGetWattProcs(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    CHECK_WATT_SCHED_EXIST();

    size_t size = sizeof(pid_t) * PWR_MAX_PROC_NUM;
    pid_t *wattProcs = (pid_t *)malloc(size);
    if (!wattProcs) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(wattProcs, size);
    int procNum = 0;
    int rspCode = ReadWattProcs(wattProcs, PWR_MAX_PROC_NUM, &procNum);
    if (rspCode != PWR_SUCCESS) {
        free(wattProcs);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)wattProcs, procNum * sizeof(pid_t));
    }
}

void ProcAddWattProcs(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    CHECK_WATT_SCHED_EXIST();

    if (req->head.dataLen < sizeof(pid_t) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    int procNum = req->head.dataLen / sizeof(pid_t);
    pid_t *procs = (pid_t *)req->data;
    for (int i = 0; i < procNum; i++) {
        (void)WriteIntToFile(WATT_PROC_PATH, *procs);
        procs++;
    }
    SendRspToClient(req, PWR_SUCCESS, NULL, 0);
}

void ProcDelWattProcs(PwrMsg *req)
{
    CHECK_SUPPORT_WATT_SCHED();
    CHECK_WATT_SCHED_EXIST();

    if (req->head.dataLen < sizeof(pid_t) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    int procNum = req->head.dataLen / sizeof(pid_t);
    pid_t *procs = (pid_t *)req->data;
    for (int i = 0; i < procNum; i++) {
        // Move the task back to the root cgroup to delete the task from the watt cgroup.
        (void)WriteIntToFile(ROOT_CGROUP_PROC_PATH, *procs);
        procs++;
    }
    SendRspToClient(req, PWR_SUCCESS, NULL, 0);
}

// smart grid
void ProcGetSmartGridState(PwrMsg *req)
{
    CHECK_SUPPORT_SMART_GRID();
    int *state = (int *)malloc(sizeof(int));
    if (!state) {
        return;
    }
    *state = PWR_DISABLE;
    char buff[PWR_STATE_LEN] = {0};
    int ret = ReadFile(SMART_GRID_STATE_PATH, buff, PWR_STATE_LEN);
    if (ret != PWR_SUCCESS) {
        free(state);
        SendRspToClient(req, ret, NULL, 0);
    } else {
        *state = atoi(buff);
        SendRspToClient(req, ret, (char *)state, sizeof(int));
    }
}

void ProcSetSmartGridState(PwrMsg *req)
{
    CHECK_SUPPORT_SMART_GRID();
    int ret = PWR_SUCCESS;
    do {
        if (req->head.dataLen != sizeof(int) || !req->data) {
            ret = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        int *state = (int *)req->data;
        if (*state != PWR_ENABLE && *state != PWR_DISABLE) {
            ret = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        char buff[PWR_STATE_LEN] = {0};
        if (sprintf(buff, "%d", *state) < 0) {
            ret = PWR_ERR_SYS_EXCEPTION;
            break;
        }
        ret = WriteFile(SMART_GRID_STATE_PATH, buff, strlen(buff));
    } while (PWR_FALSE);

    SendRspToClient(req, ret, NULL, 0);
}

void ProcGetSmartGridProcs(PwrMsg *req)
{
    CHECK_SUPPORT_SMART_GRID();
    if (req->head.dataLen < sizeof(PWR_PROC_SMART_GRID_LEVEL) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }

    PWR_PROC_SMART_GRID_LEVEL *level = (PWR_PROC_SMART_GRID_LEVEL *)req->data;
    size_t size = sizeof(PWR_PROC_SmartGridProcs) + PWR_MAX_PROC_NUM * sizeof(pid_t);
    PWR_PROC_SmartGridProcs *sgProcs = (PWR_PROC_SmartGridProcs *)malloc(size);
    if (!sgProcs) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(sgProcs, size);
    int ret = ReadSmartGridProcsByLevel(*level, sgProcs, PWR_MAX_PROC_NUM);
    if (ret != PWR_SUCCESS) {
        free(sgProcs);
        SendRspToClient(req, ret, NULL, 0);
    } else {
        SendRspToClient(req, ret, (char *)sgProcs,
            sizeof(PWR_PROC_SmartGridProcs) + sgProcs->procNum * sizeof(pid_t));
    }
}

void ProcSetSmartGridProcsLevel(PwrMsg *req)
{
    CHECK_SUPPORT_SMART_GRID();
    if (req->head.dataLen < sizeof(PWR_PROC_SmartGridProcs) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    PWR_PROC_SmartGridProcs *sgProcs = (PWR_PROC_SmartGridProcs *)req->data;
    SendRspToClient(req, WriteSmartGridProcsLevel(sgProcs), NULL, 0);
}

void ProcGetSmartGridGov(PwrMsg *req)
{
    CHECK_SUPPORT_SMART_GRID();
    size_t size = sizeof(PWR_PROC_SmartGridGov);
    PWR_PROC_SmartGridGov *sgGov = (PWR_PROC_SmartGridGov *)malloc(size);
    if (!sgGov) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(sgGov, size);
    int ret = ReadSmartGridGov(sgGov);
    if (ret != PWR_SUCCESS) {
        free(sgGov);
        SendRspToClient(req, ret, NULL, 0);
    } else {
        SendRspToClient(req, ret, (char *)sgGov, size);
    }
}

void ProcSetSmartGridGov(PwrMsg *req)
{
    CHECK_SUPPORT_SMART_GRID();
    if (req->head.dataLen < sizeof(PWR_PROC_SmartGridGov) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    PWR_PROC_SmartGridGov *sgGov = (PWR_PROC_SmartGridGov *)req->data;
    if (sgGov->sgAgentState != PWR_ENABLE && sgGov->sgAgentState != PWR_DISABLE) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    SendRspToClient(req, WriteSmartGridGov(sgGov), NULL, 0);
}

void ProcGetServiceState(PwrMsg *req)
{
    if (req->head.dataLen != sizeof(PWR_PROC_ServiceStatus) || !req->data) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    PWR_PROC_ServiceStatus *sStatus = (PWR_PROC_ServiceStatus *)req->data;
    size_t size = sizeof(PWR_PROC_ServiceStatus);
    char serviceName[MAX_SERVICE_LEN] = {0};
    int ret = CheckServiceExist(sStatus->name, serviceName);
    if (ret != PWR_SUCCESS) {
        SendRspToClient(req, ret, NULL, 0);
    }
    ret = ReadServiceState(sStatus, serviceName);
    if (ret != PWR_SUCCESS) {
        SendRspToClient(req, ret, NULL, 0);
    } else {
        req->data = NULL; // move the memory to rsp msg
        SendRspToClient(req, ret, (char *)sStatus, size);
    }
}

void ProcSetServiceState(PwrMsg *req)
{
    if (req->head.dataLen < sizeof(PWR_PROC_ServiceState) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    PWR_PROC_ServiceState *sState = (PWR_PROC_ServiceState *)req->data;
    if (sState->state != PWR_SERVICE_START && sState->state != PWR_SERVICE_STOP) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    char serviceName[MAX_SERVICE_LEN] = {0};
    int ret = CheckServiceExist(sState->name, serviceName);
    if (ret != PWR_SUCCESS) {
        SendRspToClient(req, ret, NULL, 0);
    }
    ret = ModifyServiceState(sState, serviceName);

    SendRspToClient(req, ret, NULL, 0);
}