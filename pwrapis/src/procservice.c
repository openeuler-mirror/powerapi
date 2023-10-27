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
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "utils.h"

#define WATT_CGROUP_PATH "/sys/fs/cgroup/cpu/watt_sched"
#define WATT_STATE_PATH "/sys/fs/cgroup/cpu/watt_sched/cpu.dynamic_affinity_mode"

#define WATT_ATTR_SCALE_THRESHOLD_PATH  "/proc/sys/kernel/sched_util_low_pct"
#define WATT_ATTR_DOMAIN_MASK_PATH      "/sys/fs/cgroup/cpu/watt_sched/cpu.affinity_domain_mask"
#define WATT_ATTR_SCALE_INTERVAL_PATH   "/sys/fs/cgroup/cpu/watt_sched/cpu.affinity_period_ms"
#define WATT_PROC_PATH                  "/sys/fs/cgroup/cpu/watt_sched/tasks"
#define ROOT_CGROUP_PROC_PATH           "/sys/fs/cgroup/cpu/tasks"

#define SMART_GRID_STATE_PATH "/proc/sys/kernel/smart_grid_strategy_ctrl"
#define SMART_GRID_LEVEL_PATH_D "/proc/%d/smart_grid_level"
#define SMART_GRID_LEVEL_PATH_S "/proc/%s/smart_grid_level"
#define PROC_PATH "/proc"

static int ReadWattAttrs(PWR_PROC_WattAttrs *wattAttrs)
{
    char buff[STR_LEN_FOR_INT] = {0};
    int ret = ReadFile(WATT_ATTR_SCALE_THRESHOLD_PATH, buff, STR_LEN_FOR_INT);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    wattAttrs->scaleThreshold = atoi(buff);
    ret = ReadFile(WATT_ATTR_DOMAIN_MASK_PATH, buff, STR_LEN_FOR_INT);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    wattAttrs->domainMask = atoi(buff);
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

static int ReadWattProcs(pid_t *wattProcs, size_t size, int *procNum)
{
    char *content = (char *)malloc(size);
    if (!content) {
        return PWR_ERR_SYS_EXCEPTION;
    }

    int ret = ReadFile(WATT_PROC_PATH, content, size);
    if (ret != PWR_SUCCESS) {
        free(content);
        return ret;
    }

    char **strProcs = calloc(PWR_MAX_PROC_NUM, sizeof(char *));
    if (!strProcs) {
        free(content);
        return PWR_ERR_SYS_EXCEPTION;
    }
    int num = PWR_MAX_PROC_NUM;
    char *splitBuff = StrSplit(content, LINE_SEP, strProcs, &num);
    if (!splitBuff) {
        free(strProcs);
        free(content);
        return PWR_ERR_SYS_EXCEPTION;
    }

    for (int i = 0; i < num; i++) {
        wattProcs[i] = (pid_t)atoi(strProcs[i]);
    }
    *procNum = num;
    free(splitBuff);
    free(strProcs);
    free(content);
    return PWR_SUCCESS;
}

static inline int SupportSmartGrid()
{
    if (access(SMART_GRID_STATE_PATH, F_OK) != 0) {
        return PWR_FALSE;
    }
    return PWR_TRUE;
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
            return PWR_ERR_FILE_SPRINTF_FIILED;
        }
        if (ReadFile(procLevelPath, strLevel, STR_LEN_FOR_INT) != PWR_SUCCESS) {
            continue;
        }
        if (atoi(strLevel) == level) {
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
        return PWR_ERR_FILE_SPRINTF_FIILED;
    }
    char procLevelPath[MAX_FULL_NAME] = {0};
    for (int i = 0; i < sgProcs->procNum; i++) {
        if (sprintf(procLevelPath, SMART_GRID_LEVEL_PATH_D, sgProcs->procs[i]) < 0) {
            return PWR_ERR_FILE_SPRINTF_FIILED;
        }
        (void)WriteFile(procLevelPath, strLevel, STR_LEN_FOR_INT);
    }
    return PWR_SUCCESS;
}

// public===========================================================================================
void ProcGetWattState(PwrMsg *req)
{
    int *state = (int *)malloc(sizeof(int));
    if (!state) {
        return;
    }
    *state = PWR_DISABLE;
    char buff[PWR_STATE_LEN] = {0};
    int ret = ReadFile(WATT_STATE_PATH, buff, PWR_STATE_LEN);
    if (ret == PWR_SUCCESS) {
        *state = atoi(buff);
    }
    SendRspToClient(req, 0, (char *)state, sizeof(int));
}

void ProcSetWattState(PwrMsg *req)
{
    if (req->head.dataLen != sizeof(int) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    int *state = (int *)req->data;
    if (*state != PWR_ENABLE && *state != PWR_DISABLE) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    if (access(WATT_CGROUP_PATH, F_OK) != 0 && MkDirs(WATT_CGROUP_PATH) != PWR_SUCCESS) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    int rspCode = WriteIntToFile(WATT_STATE_PATH, *state);
    SendRspToClient(req, rspCode, NULL, 0);
}

void procGetWattAttrs(PwrMsg *req)
{
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
        SendRspToClient(req, PWR_ERR_WATT_SCHED_NOT_ENABLE, NULL, 0);
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
    if (access(WATT_PROC_PATH, F_OK) != 0) {
        SendRspToClient(req, PWR_ERR_WATT_SCHED_NOT_ENABLE, NULL, 0);
        return;
    }
    size_t size = sizeof(pid_t) * PWR_MAX_PROC_NUM;
    pid_t *wattProcs = (pid_t *)malloc(size);
    if (!wattProcs) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(wattProcs, size);
    int procNum = 0;
    int rspCode = ReadWattProcs(wattProcs, size, &procNum);
    if (rspCode != PWR_SUCCESS) {
        free(wattProcs);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)wattProcs, procNum * sizeof(pid_t));
    }
}

void ProcAddWattProcs(PwrMsg *req)
{
    if (access(WATT_PROC_PATH, F_OK) != 0) {
        SendRspToClient(req, PWR_ERR_WATT_SCHED_NOT_ENABLE, NULL, 0);
        return;
    }
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
    if (access(WATT_PROC_PATH, F_OK) != 0) {
        SendRspToClient(req, PWR_ERR_WATT_SCHED_NOT_ENABLE, NULL, 0);
        return;
    }
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

void ProcGetSmartGridState(PwrMsg *req)
{
    if (!SupportSmartGrid()) {
        SendRspToClient(req, PWR_ERR_SMART_GRID_NOT_SURPPORTED, NULL, 0);
        return;
    }
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
    if (!SupportSmartGrid()) {
        SendRspToClient(req, PWR_ERR_SMART_GRID_NOT_SURPPORTED, NULL, 0);
        return;
    }
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
        ret = WriteFile(SMART_GRID_STATE_PATH, buff, PWR_STATE_LEN);
    } while (PWR_FALSE);

    SendRspToClient(req, ret, NULL, 0);
}

void ProcGetSmartGridProcs(PwrMsg *req)
{
    if (!SupportSmartGrid()) {
        SendRspToClient(req, PWR_ERR_SMART_GRID_NOT_SURPPORTED, NULL, 0);
        return;
    }
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
    if (!SupportSmartGrid()) {
        SendRspToClient(req, PWR_ERR_SMART_GRID_NOT_SURPPORTED, NULL, 0);
        return;
    }
    if (req->head.dataLen < sizeof(PWR_PROC_SmartGridProcs) || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    PWR_PROC_SmartGridProcs *sgProcs = (PWR_PROC_SmartGridProcs *)req->data;
    SendRspToClient(req, WriteSmartGridProcsLevel(sgProcs), NULL, 0);
}
