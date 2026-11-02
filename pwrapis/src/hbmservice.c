/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: heppen
 * Create: 2024-04-30
 * Description: provide hbm service
 * **************************************************************************** */

#include "hbmservice.h"

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include "config.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "hbmtask.h"

#define MAX_RETRY_COUNT 100
#define RETRY_INTERVAL_MS 100
#define HBM_EXEC_FAILURE_EXIT_STATUS 127
#define HBM_FLUSH_MODULE_NAME "hbm_flush"
#define HBM_FLUSH_PROC_PATH "/proc/hbm_flush"
#define HBM_FLUSH_TRIGGER "1\n"
#define HBM_INSMOD_PATH "/sbin/insmod"
#define HBM_CACHE_STATE_PATTERN "/sys/kernel/hbm_cache/*/state"
#define HBM_CACHE_STATUS_PATTERN "/sys/kernel/hbm_cache/*/firmware_node/status"
#define HBM_DEVICE_STATE_PATTERN "/sys/devices/system/container/PNP0A06*/state"
#define HBM_DEVICE_STATUS_PATTERN "/sys/devices/system/container/PNP0A06*/firmware_node/PNP0C80*/status"
#define HBM_FIRMWARE_STATUS_ON "15"
#define HBM_DEVICE_FIRMWARE_STATUS_OFF "13"
#define HBM_CACHE_FIRMWARE_STATUS_OFF "0"

static long long GetTimeUs(void)
{
    struct timeval now;
    (void)gettimeofday(&now, NULL);
    return now.tv_sec * 1000000LL + now.tv_usec;
}

static int SetStateFiles(HbmTask *task, const char *pattern, const char *state, const char *errMsg)
{
    glob_t paths = {0};
    int globRet = glob(pattern, GLOB_NOSORT, NULL, &paths);
    if (globRet != 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "%s", errMsg);
        globfree(&paths);
        return PWR_ERR_COMMON;
    }

    int ret = PWR_SUCCESS;
    for (size_t i = 0; i < paths.gl_pathc; ++i) {
        if (IsHbmTaskTimedOut(task)) {
            ret = PWR_ERR_HBM_OPERATION_TIMEOUT;
            break;
        }
        int writeRet = WriteFile(paths.gl_pathv[i], state, strlen(state));
        if (IsHbmTaskTimedOut(task)) {
            ret = PWR_ERR_HBM_OPERATION_TIMEOUT;
            break;
        }
        if (writeRet != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "%s, path:%s", errMsg, paths.gl_pathv[i]);
            ret = PWR_ERR_COMMON;
            break;
        }
    }
    globfree(&paths);
    return ret;
}

static int BuildPath(char *path, size_t pathSize, const char *directory,
    const char *entry, const char *file)
{
    if (!path || pathSize == 0 || !directory || !entry) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    const char *parts[] = {directory, "/", entry, "/", file};
    size_t partCount = file ? sizeof(parts) / sizeof(parts[0]) : 3;
    size_t pos = 0;
    for (size_t i = 0; i < partCount; ++i) {
        for (size_t j = 0; parts[i][j] != '\0'; ++j) {
            if (pos + 1 >= pathSize) {
                path[0] = '\0';
                return PWR_ERR_COMMON;
            }
            path[pos++] = parts[i][j];
        }
    }
    path[pos] = '\0';
    return PWR_SUCCESS;
}

static int RunInsmod(const char *modulePath)
{
    pid_t pid = fork();
    if (pid < 0) {
        return PWR_ERR_COMMON;
    }
    if (pid == 0) {
        char programName[] = "insmod";
        char *const argv[] = {programName, (char *)modulePath, NULL};
        char *const envp[] = {NULL};
        execve(HBM_INSMOD_PATH, argv, envp);
        _exit(HBM_EXEC_FAILURE_EXIT_STATUS);
    }

    int status;
    pid_t waitRet;
    do {
        waitRet = waitpid(pid, &status, 0);
    } while (waitRet < 0 && errno == EINTR);
    if (waitRet < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return PWR_ERR_COMMON;
    }
    return PWR_SUCCESS;
}

static int IsNodeEmptyCpuList(const char *nodePath)
{
    char cpuListFile[MAX_FULL_NAME];
    FILE *cpuListFp;
    char cpuListBuf[256];

    if (BuildPath(cpuListFile, sizeof(cpuListFile), nodePath, "cpulist", NULL) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to build cpulist path for %s", nodePath);
        return 0;
    }
    cpuListFp = fopen(cpuListFile, "r");
    if (cpuListFp == NULL) {
        return 0;
    }

    if (fgets(cpuListBuf, sizeof(cpuListBuf), cpuListFp) != NULL &&
        (strlen(cpuListBuf) == 0 || strcmp(cpuListBuf, "\n") == 0)) {
        fclose(cpuListFp);
        return 1;
    }

    fclose(cpuListFp);
    return 0;
}

static int CheckMemoryRemovable(const char *nodePath, const char *blockName)
{
    char removableFile[MAX_FULL_NAME];
    char removable[PWR_MAX_NAME_LEN] = {0};
    long long startUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM memory removable check start. node:%s, block:%s", nodePath, blockName);

    int ret = BuildPath(removableFile, sizeof(removableFile), nodePath, blockName, "removable");
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM,
            "Failed to build removable path. node:%s, block:%s", nodePath, blockName);
        ret = PWR_ERR_COMMON;
    } else {
        ret = ReadFile(removableFile, removable, sizeof(removable));
        if (ret != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM,
                "Failed to read removable. node:%s, block:%s, file:%s, ret:%d",
                nodePath, blockName, removableFile, ret);
        } else if (strcmp(removable, "0") == 0) {
            Logger(ERROR, MD_NM_SVR_HBM,
                "HBM memory block is not removable. node:%s, block:%s, removable:%s",
                nodePath, blockName, removable);
            ret = PWR_ERR_COMMON;
        } else if (strcmp(removable, "1") != 0) {
            Logger(ERROR, MD_NM_SVR_HBM,
                "Invalid removable value. node:%s, block:%s, removable:%s",
                nodePath, blockName, removable);
            ret = PWR_ERR_COMMON;
        }
    }

    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM memory removable check finish. node:%s, block:%s, removable:%s, ret:%d, durationUs:%lld",
        nodePath, blockName, removable, ret, GetTimeUs() - startUs);
    return ret;
}

typedef struct {
    const char *nodePath;
    const char *blockName;
    const char *state;
    const char *stateFile;
    const char *currentState;
    size_t progressIndex;
    long long startUs;
} MemoryBlockOperation;

static int WriteMemoryBlockState(HbmTask *task, const MemoryBlockOperation *op)
{
    // Check each block immediately before offlining.
    if (SetHbmTaskPhase(task, "check_removable",
        op->nodePath, op->blockName) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    if (CheckMemoryRemovable(op->nodePath, op->blockName) != PWR_SUCCESS) {
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM memory block finish. node:%s, block:%s, beforeState:%s, target:%s, "
            "action:check_removable, ret:%d, durationUs:%lld",
            op->nodePath, op->blockName, op->currentState, op->state, PWR_ERR_COMMON, GetTimeUs() - op->startUs);
        return PWR_ERR_COMMON;
    }

    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM memory block write start. node:%s, block:%s, beforeState:%s, target:%s",
        op->nodePath, op->blockName, op->currentState, op->state);
    if (SetHbmTaskPhase(task, "write_memory_offline",
        op->nodePath, op->blockName) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int writeRet = WriteFile(op->stateFile, op->state, strlen(op->state));
    if (IsHbmTaskTimedOut(task)) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    if (writeRet != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to write %s to memory state file %s", op->state, op->stateFile);
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM memory block finish. node:%s, block:%s, beforeState:%s, target:%s, "
            "action:write, writeResult:failed, ret:%d, durationUs:%lld",
            op->nodePath, op->blockName, op->currentState, op->state, PWR_ERR_COMMON, GetTimeUs() - op->startUs);
        return PWR_ERR_COMMON;
    }
    CompleteHbmProgress(task, op->progressIndex, 0);
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM memory block finish. node:%s, block:%s, beforeState:%s, target:%s, "
        "action:write, writeResult:success, ret:%d, durationUs:%lld",
        op->nodePath, op->blockName, op->currentState, op->state, PWR_SUCCESS, GetTimeUs() - op->startUs);
    return PWR_SUCCESS;
}

static int ProcessMemoryBlock(HbmTask *task, const char *nodePath, const char *blockName,
    const char *state)
{
    char stateFile[MAX_FULL_NAME];
    if (BuildPath(stateFile, sizeof(stateFile), nodePath, blockName, "state") != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Buffer overflow detected in memoryStateFile");
        return PWR_ERR_COMMON;
    }

    long long startUs = GetTimeUs();
    size_t progressIndex = 0;
    if (PrepareHbmProgress(task, nodePath, blockName, &progressIndex) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to record HBM progress. node:%s, block:%s", nodePath, blockName);
        return PWR_ERR_COMMON;
    }
    if (SetHbmTaskPhase(task, "read_memory_state",
        nodePath, blockName) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM memory block start. node:%s, block:%s, target:%s", nodePath, blockName, state);
    /* State read before the operation; not a post-write readback. */
    char currentState[PWR_MAX_NAME_LEN] = {0};
    if (ReadFile(stateFile, currentState, sizeof(currentState)) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to read memory state file %s", stateFile);
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM memory block finish. node:%s, block:%s, target:%s, action:read, ret:%d, durationUs:%lld",
            nodePath, blockName, state, PWR_ERR_COMMON, GetTimeUs() - startUs);
        return PWR_ERR_COMMON;
    }
    if (strcmp(currentState, state) == 0) {
        CompleteHbmProgress(task, progressIndex, 1);
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM memory block finish. node:%s, block:%s, beforeState:%s, target:%s, action:skip, ret:%d, "
            "durationUs:%lld",
            nodePath, blockName, currentState, state, PWR_SUCCESS, GetTimeUs() - startUs);
        return PWR_SUCCESS;
    }
    MemoryBlockOperation op = {nodePath, blockName, state, stateFile, currentState, progressIndex, startUs};
    return WriteMemoryBlockState(task, &op);
}

static int SetMemoryState(HbmTask *task, const char *nodePath, const char *state)
{
    if (SetHbmTaskPhase(task, "scan_memory", nodePath, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    long long nodeStartUs = GetTimeUs();
    DIR *dir;
    struct dirent *dirEntry;

    dir = opendir(nodePath);
    if (dir == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open memory directory");
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM memory node finish. node:%s, target:%s, ret:%d, durationUs:%lld",
            nodePath, state, PWR_ERR_COMMON, GetTimeUs() - nodeStartUs);
        return PWR_ERR_COMMON;
    }

    Logger(DEBUG, MD_NM_SVR_HBM, "HBM memory node start. node:%s, target:%s", nodePath, state);

    while ((dirEntry = readdir(dir)) != NULL) {
        if (strncmp(dirEntry->d_name, "memory", strlen("memory")) != 0) {
            continue;
        }

        int ret = ProcessMemoryBlock(task, nodePath, dirEntry->d_name, state);
        if (ret != PWR_SUCCESS) {
            closedir(dir);
            return ret;
        }
    }

    closedir(dir);
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM memory node finish. node:%s, target:%s, ret:%d, durationUs:%lld",
        nodePath, state, PWR_SUCCESS, GetTimeUs() - nodeStartUs);
    return PWR_SUCCESS;
}

static int OfflineMemoryState(HbmTask *task, const char *nodePath)
{
    return SetMemoryState(task, nodePath, "offline");
}

static int OfflineHbmNode(HbmTask *task, const char *nodePath, int *offlinedCnt)
{
    if (SetHbmTaskPhase(task, "check_node_cpus", nodePath, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    if (!IsNodeEmptyCpuList(nodePath)) {
        return PWR_SUCCESS;
    }

    size_t nodeIndex;
    if (PrepareHbmProgress(task, nodePath, NULL, &nodeIndex) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to record HBM node progress. node:%s", nodePath);
        return PWR_ERR_COMMON;
    }
    (*offlinedCnt)++;

    if (OfflineMemoryState(task, nodePath) != PWR_SUCCESS) {
        if (IsHbmTaskTimedOut(task)) {
            return PWR_ERR_HBM_OPERATION_TIMEOUT;
        }
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to offline memory of node %s", nodePath);
        return PWR_ERR_HBM_OFFLINE_MEMORY_FAILED;
    }
    CompleteHbmProgress(task, nodeIndex, 0);
    return PWR_SUCCESS;
}

static int OfflineAllHBMNode(HbmTask *task, int *offlinedCnt)
{
    if (SetHbmTaskPhase(task, "scan_nodes", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    long long startUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM, "HBM phase start. phase:offline_memory");
    DIR *dirPtr = opendir("/sys/devices/system/node");
    if (dirPtr == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open /sys/devices/system/node dir");
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM phase finish. phase:offline_memory, nodeCount:0, ret:%d, durationUs:%lld",
            PWR_ERR_FILE_OPEN_FAILED, GetTimeUs() - startUs);
        return PWR_ERR_FILE_OPEN_FAILED;
    }

    *offlinedCnt = 0;
    int errCode = PWR_SUCCESS;
    struct dirent *dirEntry;

    while ((dirEntry = readdir(dirPtr)) != NULL) {
        if (strncmp(dirEntry->d_name, "node", strlen("node")) != 0) {
            continue;
        }

        char nodePath[MAX_FULL_NAME];
        int ret = BuildPath(nodePath, sizeof(nodePath), "/sys/devices/system", "node", dirEntry->d_name);
        if (ret != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to build node path for %s", dirEntry->d_name);
            continue;
        }

        errCode = OfflineHbmNode(task, nodePath, offlinedCnt);
        if (errCode != PWR_SUCCESS) {
            break;
        }
    }

    closedir(dirPtr);
    if (IsHbmTaskTimedOut(task)) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }

    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:offline_memory, nodeCount:%d, ret:%d, durationUs:%lld",
        *offlinedCnt, errCode, GetTimeUs() - startUs);

    return errCode;
}

static int LoadHbmFlushModule(HbmTask *task, int *needUnload)
{
    *needUnload = 0;

    if (access(HBM_FLUSH_PROC_PATH, W_OK) == 0) {
        *needUnload = 1;
        return PWR_SUCCESS;
    }

    if (errno != ENOENT) {
        *needUnload = 1;
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to access %s. errno:%d, %s",
               HBM_FLUSH_PROC_PATH, errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    struct utsname uts;
    if (uname(&uts) != 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to get kernel release. errno:%d, %s", errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    char modulePath[MAX_FULL_NAME] = {0};
    int ret = BuildPath(modulePath, sizeof(modulePath), "/lib/modules", uts.release,
        HBM_FLUSH_MODULE_NAME ".ko");
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to build %s.ko path", HBM_FLUSH_MODULE_NAME);
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    if (access(modulePath, R_OK) != 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to access %s. errno:%d, %s",
               modulePath, errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    *needUnload = 1;
    if (IsHbmTaskTimedOut(task)) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    if (RunInsmod(modulePath) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to insmod %s", modulePath);
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    if (IsHbmTaskTimedOut(task)) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    if (access(HBM_FLUSH_PROC_PATH, W_OK) != 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to access %s after insmod %s.ko. errno:%d, %s",
               HBM_FLUSH_PROC_PATH, HBM_FLUSH_MODULE_NAME, errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    return PWR_SUCCESS;
}

static int UnloadHbmFlushModule(void)
{
    if (system("rmmod " HBM_FLUSH_MODULE_NAME) != 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to rmmod %s.ko module", HBM_FLUSH_MODULE_NAME);
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    return PWR_SUCCESS;
}

static int TriggerHbmCacheFlush(HbmTask *task)
{
    int fd = open(HBM_FLUSH_PROC_PATH, O_WRONLY);
    if (fd < 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open %s. errno:%d, %s",
               HBM_FLUSH_PROC_PATH, errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    if (IsHbmTaskTimedOut(task)) {
        close(fd);
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    size_t triggerLen = strlen(HBM_FLUSH_TRIGGER);
    ssize_t writeLen = write(fd, HBM_FLUSH_TRIGGER, triggerLen);
    if (writeLen != (ssize_t)triggerLen) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to trigger HBM cache flush. errno:%d, %s",
               errno, strerror(errno));
        (void)close(fd);
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    if (close(fd) != 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to close %s after cache flush. errno:%d, %s",
               HBM_FLUSH_PROC_PATH, errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
    }

    return PWR_SUCCESS;
}

static int FlushHbmCacheBeforePowerOff(HbmTask *task)
{
    long long startUs = GetTimeUs();
    long long stepStartUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM, "HBM phase start. phase:flush_cache");
    Logger(DEBUG, MD_NM_SVR_HBM, "HBM flush step start. step:load_module");
    int needUnload = 0;
    if (SetHbmTaskPhase(task, "flush_load_module", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int ret = LoadHbmFlushModule(task, &needUnload);
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM flush step finish. step:load_module, ret:%d, needUnload:%d, durationUs:%lld",
        ret, needUnload, GetTimeUs() - stepStartUs);
    if (ret == PWR_SUCCESS) {
        stepStartUs = GetTimeUs();
        Logger(DEBUG, MD_NM_SVR_HBM, "HBM flush step start. step:trigger_flush");
        if (SetHbmTaskPhase(task, "flush_trigger", NULL, NULL) != PWR_SUCCESS) {
            return PWR_ERR_HBM_OPERATION_TIMEOUT;
        }
        ret = TriggerHbmCacheFlush(task);
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM flush step finish. step:trigger_flush, ret:%d, durationUs:%lld",
            ret, GetTimeUs() - stepStartUs);
    }

    stepStartUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM flush step start. step:unload_module, required:%d", needUnload);
    if (SetHbmTaskPhase(task, "flush_unload_module", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int unloadRet = needUnload ? UnloadHbmFlushModule() : PWR_SUCCESS;
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM flush step finish. step:unload_module, ret:%d, durationUs:%lld",
        unloadRet, GetTimeUs() - stepStartUs);
    if (ret != PWR_SUCCESS) {
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM phase finish. phase:flush_cache, ret:%d, durationUs:%lld",
            ret, GetTimeUs() - startUs);
        return ret;
    }

    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:flush_cache, ret:%d, durationUs:%lld",
        unloadRet, GetTimeUs() - startUs);
    return unloadRet;
}

static int GetHbmMode(PWR_HBM_SYS_STATE *state)
{
    *state = PWR_HBM_NOT_SUPPORT;

    char hbmModeFile[] = "/sys/firmware/efi/efivars/MemoryOnChipMode-21f3b3c5-946d-41c1-838c-194e48aa41e2";
    if (access(hbmModeFile, F_OK) != 0) {
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }

    char hbmCmd[] =
        "hexdump /sys/firmware/efi/efivars/MemoryOnChipMode-21f3b3c5-946d-41c1-838c-194e48aa41e2 | grep '0000000 0007 0000 "
        "0001' | wc -l";
    FILE *fp = popen(hbmCmd, "r");
    if (fp == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed get hbm mode");
        return PWR_ERR_COMMON;
    }

    char resultBuf[PWR_MAX_STRING_LEN] = {0};
    if (fgets(resultBuf, sizeof(resultBuf), fp) != NULL) {
        int count = atoi(resultBuf);
        if (count == 0) {
            *state = PWR_HBM_FLAT_MOD;
        } else if (count == 1) {
            *state = PWR_HBM_CACHE_MOD;
        } else {
            *state = PWR_HBM_NOT_SUPPORT;
        }
    }

    pclose(fp);

    return PWR_SUCCESS;
}

void GetHbmSysState(PwrMsg *req)
{
    PWR_HBM_SYS_STATE *state = (PWR_HBM_SYS_STATE *)malloc(sizeof(PWR_HBM_SYS_STATE));
    if (!state) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    *state = PWR_HBM_NOT_SUPPORT;
    int rspCode = GetHbmMode(state);
    if (rspCode != PWR_SUCCESS) {
        free(state);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)state, sizeof(PWR_HBM_SYS_STATE));
    }
}

/* Map a firmware _STA value to a node power state. */
static PWR_HBM_NODE_PWR_STATE ParseFirmwareStatus(const char *status, const char *onValue,
    const char *offValue)
{
    if (strcmp(status, onValue) == 0) {
        return PWR_HBM_NODE_ON;
    }
    if (strcmp(status, offValue) == 0) {
        return PWR_HBM_NODE_OFF;
    }
    return PWR_HBM_NODE_UNKNOWN;
}

/* Best-effort driver loading so that queries work right after boot, same as the set path. */
static void EnsureHbmDriverForQuery(const char *checkPattern, const char *moduleName)
{
    glob_t paths = {0};
    int globRet = glob(checkPattern, GLOB_NOSORT, NULL, &paths);
    if (globRet == 0 && paths.gl_pathc > 0) {
        globfree(&paths);
        return;
    }
    globfree(&paths);

    char cmd[PWR_MAX_NAME_LEN] = {0};
    int ret = snprintf(cmd, sizeof(cmd), "modprobe %s", moduleName);
    if (ret <= 0 || ret >= (int)sizeof(cmd)) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to build modprobe command for %s", moduleName);
        return;
    }
    if (system(cmd) != 0) {
        Logger(WARNING, MD_NM_SVR_HBM, "Failed to load %s for HBM state query", moduleName);
    }
}

/* Aggregate device statuses: any unrecognized status wins, then on/off
 * disagreement, else unanimous. */
static PWR_HBM_NODE_PWR_STATE AggregateNodeState(int onCnt, int offCnt, int unknownCnt)
{
    if (unknownCnt > 0) {
        return PWR_HBM_NODE_UNKNOWN;
    }
    if (onCnt > 0 && offCnt > 0) {
        return PWR_HBM_NODE_PWR_MISMATCH;
    }
    if (onCnt > 0) {
        return PWR_HBM_NODE_ON;
    }
    return PWR_HBM_NODE_OFF;
}

/* Shell one-liner counting memory block states over all HBM nodes (NUMA nodes
 * whose cpulist is empty). Prints "<online> <offline> <other>". Blocks absent
 * from sysfs are not counted at all; blocks whose state cannot be read count
 * as other. */
#define HBM_BLOCK_STATE_CMD \
    "on=0; off=0; other=0; " \
    "for node in /sys/devices/system/node/node*; do " \
    "[ -e \"$node\" ] || continue; " \
    "[ -s \"$node/cpulist\" ] && continue; " \
    "for block in \"$node\"/memory*; do " \
    "[ -f \"$block/state\" ] || continue; " \
    "blockState=$(cat \"$block/state\" 2>/dev/null); " \
    "case \"$blockState\" in " \
    "online) on=$((on+1));; " \
    "offline) off=$((off+1));; " \
    "*) other=$((other+1));; " \
    "esac; done; done; " \
    "echo \"$on $off $other\""

/* Count the memory block states of all HBM nodes. Blocks absent from sysfs
 * (firmware removes them after powering the memory off) are simply not
 * counted; the caller reads zero online and zero other as "all offline or
 * absent". */
static int CountHbmBlockStates(int *onlineCnt, int *offlineCnt, int *otherCnt)
{
    *onlineCnt = 0;
    *offlineCnt = 0;
    *otherCnt = 0;

    FILE *fp = popen(HBM_BLOCK_STATE_CMD, "r");
    if (fp == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to run HBM block state query");
        return PWR_ERR_COMMON;
    }
    char resultBuf[PWR_MAX_STRING_LEN] = {0};
    int matched = 0;
    if (fgets(resultBuf, sizeof(resultBuf), fp) != NULL) {
        matched = sscanf(resultBuf, "%d %d %d", onlineCnt, offlineCnt, otherCnt);
    }
    pclose(fp);
    if (matched != 3) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to parse HBM block state counts. buf:%s", resultBuf);
        return PWR_ERR_COMMON;
    }
    return PWR_SUCCESS;
}

/*
 * Flat mode: each PNP0A06 container's PNP0C80 memory devices report the power state
 * in firmware_node status (15 on, 13 off), and each HBM node (a NUMA node whose
 * cpulist is empty) exposes its memory blocks' states. Judgment uses two levels:
 *   ON requires every device status 15 AND every memory block online;
 *   OFF requires every device status 13 AND every block offline or absent from
 *   sysfs (firmware removes the blocks after powering the memory off);
 *   devices disagreeing on/off report PWR_MISMATCH;
 *   unanimous statuses not backed by the blocks report MIXED_BLOCK;
 *   any unrecognized firmware status reports UNKNOWN.
 * Device state files do not participate: power-off writes devices strictly after
 * ALL blocks are offlined (a stuck device write leaves the blocks mixed, which
 * the block level reports), and power-on cannot reach "all status 15" while a
 * device online-write failed (that device keeps status 13).
 */
static int CollectFlatNodeState(PWR_HBM_NODE_PWR_STATE *state)
{
    glob_t statusPaths = {0};
    int globRet = glob(HBM_DEVICE_STATUS_PATTERN, GLOB_NOSORT, NULL, &statusPaths);
    if (globRet != 0 || statusPaths.gl_pathc == 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "No HBM device status found in flat mode");
        globfree(&statusPaths);
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }

    int onCnt = 0;
    int offCnt = 0;
    int unknownCnt = 0;
    for (size_t i = 0; i < statusPaths.gl_pathc; ++i) {
        char status[PWR_MAX_NAME_LEN] = {0};
        if (ReadFile(statusPaths.gl_pathv[i], status, sizeof(status)) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to read HBM device status %s",
                statusPaths.gl_pathv[i]);
            ++unknownCnt;
            continue;
        }
        PWR_HBM_NODE_PWR_STATE cur =
            ParseFirmwareStatus(status, HBM_FIRMWARE_STATUS_ON, HBM_DEVICE_FIRMWARE_STATUS_OFF);
        if (cur == PWR_HBM_NODE_ON) {
            ++onCnt;
        } else if (cur == PWR_HBM_NODE_OFF) {
            ++offCnt;
        } else {
            ++unknownCnt;
        }
    }
    globfree(&statusPaths);

    int blockOnlineCnt = 0;
    int blockOfflineCnt = 0;
    int blockOtherCnt = 0;
    int ret = CountHbmBlockStates(&blockOnlineCnt, &blockOfflineCnt, &blockOtherCnt);
    if (ret != PWR_SUCCESS) {
        return ret;
    }

    /* "All online" needs at least one visible block; absent blocks read offline. */
    int blockAllOnline = (blockOnlineCnt > 0 && blockOfflineCnt == 0 && blockOtherCnt == 0);
    int blockAllOffline = (blockOnlineCnt == 0 && blockOtherCnt == 0);

    PWR_HBM_NODE_PWR_STATE statusState = AggregateNodeState(onCnt, offCnt, unknownCnt);
    PWR_HBM_NODE_PWR_STATE result = statusState;
    if (statusState == PWR_HBM_NODE_ON && !blockAllOnline) {
        result = PWR_HBM_NODE_MIXED_BLOCK;
    } else if (statusState == PWR_HBM_NODE_OFF && !blockAllOffline) {
        result = PWR_HBM_NODE_MIXED_BLOCK;
    }

    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM flat node state detail. result:%d, status:on=%d off=%d unknown=%d, "
        "block:online=%d offline=%d other=%d",
        (int)result, onCnt, offCnt, unknownCnt,
        blockOnlineCnt, blockOfflineCnt, blockOtherCnt);
    *state = result;
    return PWR_SUCCESS;
}

/*
 * Cache mode: each hbm_cache device reports the power state in firmware_node status
 * (15 on, 0 off). There is no block level to consult, so the judgment rests on the
 * device statuses alone and never reports PWR_HBM_NODE_MIXED_BLOCK.
 */
static int CollectCacheNodeState(PWR_HBM_NODE_PWR_STATE *state)
{
    EnsureHbmDriverForQuery(HBM_CACHE_STATE_PATTERN, "hisi_hbmcache");

    glob_t statusPaths = {0};
    int globRet = glob(HBM_CACHE_STATUS_PATTERN, GLOB_NOSORT, NULL, &statusPaths);
    if (globRet != 0 || statusPaths.gl_pathc == 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "No HBM cache devices found in cache mode");
        globfree(&statusPaths);
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }

    int onCnt = 0;
    int offCnt = 0;
    int unknownCnt = 0;
    for (size_t i = 0; i < statusPaths.gl_pathc; ++i) {
        char status[PWR_MAX_NAME_LEN] = {0};
        if (ReadFile(statusPaths.gl_pathv[i], status, sizeof(status)) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to read HBM cache status %s",
                statusPaths.gl_pathv[i]);
            ++unknownCnt;
            continue;
        }
        PWR_HBM_NODE_PWR_STATE cur =
            ParseFirmwareStatus(status, HBM_FIRMWARE_STATUS_ON, HBM_CACHE_FIRMWARE_STATUS_OFF);
        if (cur == PWR_HBM_NODE_ON) {
            ++onCnt;
        } else if (cur == PWR_HBM_NODE_OFF) {
            ++offCnt;
        } else {
            ++unknownCnt;
        }
    }
    globfree(&statusPaths);

    Logger(DEBUG, MD_NM_SVR_HBM, "HBM cache node states. on:%d, off:%d, unknown:%d",
        onCnt, offCnt, unknownCnt);
    *state = AggregateNodeState(onCnt, offCnt, unknownCnt);
    return PWR_SUCCESS;
}

void GetHbmNodeState(PwrMsg *req)
{
    PWR_HBM_NODE_PWR_STATE *state =
        (PWR_HBM_NODE_PWR_STATE *)malloc(sizeof(PWR_HBM_NODE_PWR_STATE));
    if (!state) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    *state = PWR_HBM_NODE_UNKNOWN;

    PWR_HBM_SYS_STATE mode = PWR_HBM_NOT_SUPPORT;
    int rspCode = GetHbmMode(&mode);
    if (rspCode != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "GetHbmNodeState: failed to detect hbm mode. ret:%d", rspCode);
    } else if (mode == PWR_HBM_FLAT_MOD) {
        rspCode = CollectFlatNodeState(state);
    } else if (mode == PWR_HBM_CACHE_MOD) {
        rspCode = CollectCacheNodeState(state);
    } else {
        Logger(ERROR, MD_NM_SVR_HBM, "GetHbmNodeState: unsupported hbm mode:%d", mode);
        rspCode = PWR_ERR_HBM_NOT_SUPPORTED;
    }

    if (rspCode != PWR_SUCCESS) {
        free(state);
        SendRspToClient(req, rspCode, NULL, 0);
        return;
    }
    Logger(DEBUG, MD_NM_SVR_HBM, "GetHbmNodeState. mode:%d, state:%d", mode, (int)(*state));
    SendRspToClient(req, rspCode, (char *)state, sizeof(PWR_HBM_NODE_PWR_STATE));
    free(state);
}

/* ==================== Node-level HBM reset capability ====================
 * The capability is derived from the CpuBoard CPLD versions reported by BMC:
 *   ipmitool fru                                        -> enumerate CpuBoard FRU ids
 *   ipmitool raw 0x30 0x90 0x08 <fruId> 0x02 0x00 0xff  -> CPLD versions
 * The raw response is a hex byte stream, e.g. "80 28 55 35 39 29 34 2e 30 38 ..."
 * which decodes to "<rc>(U59)4.08;(U130)4.08". Node-level reset is supported
 * only when every CPLD version found is 3.11 or higher.
 */
#define HBM_CPLD_MIN_VER_MAJOR 3
#define HBM_CPLD_MIN_VER_MINOR 11
#define HBM_CPLD_MAX_BOARDS 8
#define HBM_CPLD_TEXT_BUF_LEN 512

/* CpuBoard FRU ids are static per boot (BMC SDR configuration), so the
 * ipmitool fru enumeration (~5s) runs once per service lifetime and the
 * result is reused afterwards. Cleared when a raw CPLD query fails so the
 * next call re-enumerates. */
static int g_cachedCpuBoardFruIds[HBM_CPLD_MAX_BOARDS];
static uint32_t g_cachedCpuBoardFruNum = 0;

static void InvalidateCpuBoardFruIds(void)
{
    g_cachedCpuBoardFruNum = 0;
}

/* Parse "CpuBoard1 (ID 16)" style lines from `ipmitool fru` output. */
static int GetCpuBoardFruIds(int fruIds[], uint32_t maxNum, uint32_t *num)
{
    if (g_cachedCpuBoardFruNum > 0) {
        uint32_t copyNum = (g_cachedCpuBoardFruNum < maxNum) ? g_cachedCpuBoardFruNum : maxNum;
        memcpy(fruIds, g_cachedCpuBoardFruIds, copyNum * sizeof(int));
        *num = copyNum;
        Logger(DEBUG, MD_NM_SVR_HBM, "CpuBoard fruIds from cache. num:%u", copyNum);
        return PWR_SUCCESS;
    }
    FILE *fp = popen("ipmitool fru", "r");
    if (fp == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "popen ipmitool fru failed.");
        return PWR_ERR_COMMON;
    }
    char line[PWR_MAX_STRING_LEN] = {0};
    uint32_t cnt = 0;
    while (cnt < maxNum && fgets(line, sizeof(line), fp) != NULL) {
        char *board = strstr(line, "CpuBoard");
        if (board == NULL) {
            continue;
        }
        char *idTag = strstr(board, "(ID ");
        if (idTag == NULL) {
            continue;
        }
        int fruId = -1;
        if (sscanf(idTag, "(ID %i)", &fruId) != 1 || fruId < 0) {
            continue;
        }
        Logger(DEBUG, MD_NM_SVR_HBM, "CpuBoard found. fruId:0x%02x", (unsigned)fruId);
        fruIds[cnt++] = fruId;
    }
    pclose(fp);
    if (cnt == 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "no CpuBoard FRU found from ipmitool fru");
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }
    memcpy(g_cachedCpuBoardFruIds, fruIds, cnt * sizeof(int));
    g_cachedCpuBoardFruNum = cnt;
    *num = cnt;
    return PWR_SUCCESS;
}

/* Query the CPLD versions of one board and decode the hex byte stream into
 * printable ASCII text, e.g. "(U59)4.08;(U130)4.08". */
static int ReadCpldVersionText(int fruId, char *text, size_t textSize)
{
    char cmd[PWR_MAX_STRING_LEN] = {0};
    int ret = snprintf(cmd, sizeof(cmd),
        "ipmitool raw 0x30 0x90 0x08 0x%02x 0x02 0x00 0xff", (unsigned)fruId);
    if (ret <= 0 || ret >= (int)sizeof(cmd)) {
        return PWR_ERR_COMMON;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "popen [%s] failed.", cmd);
        return PWR_ERR_COMMON;
    }
    char buf[PWR_MAX_STRING_LEN] = {0};
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        pclose(fp);
        Logger(ERROR, MD_NM_SVR_HBM, "read cpld version of fru 0x%02x failed.", (unsigned)fruId);
        InvalidateCpuBoardFruIds();
        return PWR_ERR_COMMON;
    }
    pclose(fp);

    /* The first byte is the return code; the remaining bytes are ASCII text. */
    size_t pos = 0;
    const char *token = strtok(buf, " \t\r\n");
    int first = 1;
    while (token != NULL && pos + 1 < textSize) {
        if (!first) {
            unsigned int byte = 0;
            if (sscanf(token, "%x", &byte) == 1 && byte >= 0x20 && byte <= 0x7e) {
                text[pos++] = (char)byte;
            }
        }
        first = 0;
        token = strtok(NULL, " \t\r\n");
    }
    text[pos] = '\0';
    if (pos == 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "cpld version response of fru 0x%02x is empty.", (unsigned)fruId);
        InvalidateCpuBoardFruIds();
        return PWR_ERR_COMMON;
    }
    Logger(DEBUG, MD_NM_SVR_HBM, "cpld version text of fru 0x%02x: %s", (unsigned)fruId, text);
    return PWR_SUCCESS;
}

static int CpldVersionAtLeast(int major, int minor)
{
    if (major > HBM_CPLD_MIN_VER_MAJOR) {
        return 1;
    }
    return (major == HBM_CPLD_MIN_VER_MAJOR) && (minor >= HBM_CPLD_MIN_VER_MINOR);
}

/* Scan the text for every "major.minor" version string. All versions found
 * must satisfy the minimum requirement, otherwise the capability is disabled. */
static int CheckCpldVersions(const char *text, int *supported)
{
    *supported = PWR_ENABLE;
    int verCnt = 0;
    const char *p = text;
    while (*p != '\0') {
        if (isdigit((unsigned char)*p)) {
            int major = 0;
            int minor = 0;
            int consumed = 0;
            if (sscanf(p, "%d.%d%n", &major, &minor, &consumed) == 2 &&
                consumed > 0 && memchr(p, '.', (size_t)consumed) != NULL) {
                verCnt++;
                Logger(DEBUG, MD_NM_SVR_HBM, "CPLD version found: %d.%d", major, minor);
                if (!CpldVersionAtLeast(major, minor)) {
                    *supported = PWR_DISABLE;
                }
                p += consumed;
                continue;
            }
        }
        p++;
    }
    if (verCnt == 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "no CPLD version found in response [%s]", text);
        return PWR_ERR_COMMON;
    }
    return PWR_SUCCESS;
}

/* Supported only when every CPLD on every CpuBoard is >= 3.11. */
static int CheckNodeResetCapByCpld(int *supported)
{
    int fruIds[HBM_CPLD_MAX_BOARDS];
    uint32_t boardNum = 0;
    int ret = GetCpuBoardFruIds(fruIds, HBM_CPLD_MAX_BOARDS, &boardNum);
    if (ret != PWR_SUCCESS) {
        return ret;
    }

    *supported = PWR_ENABLE;
    for (uint32_t i = 0; i < boardNum; ++i) {
        char text[HBM_CPLD_TEXT_BUF_LEN] = {0};
        ret = ReadCpldVersionText(fruIds[i], text, sizeof(text));
        if (ret != PWR_SUCCESS) {
            return ret;
        }
        int boardSupported = PWR_DISABLE;
        ret = CheckCpldVersions(text, &boardSupported);
        if (ret != PWR_SUCCESS) {
            return ret;
        }
        Logger(DEBUG, MD_NM_SVR_HBM, "CpuBoard fru 0x%02x node reset cap: %d",
            (unsigned)fruIds[i], boardSupported);
        if (boardSupported == PWR_DISABLE) {
            *supported = PWR_DISABLE;
        }
    }
    return PWR_SUCCESS;
}

void GetHbmNodeResetCap(PwrMsg *req)
{
    int *supported = (int *)malloc(sizeof(int));
    if (!supported) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    *supported = PWR_DISABLE;
    int rspCode = CheckNodeResetCapByCpld(supported);
    if (rspCode != PWR_SUCCESS) {
        free(supported);
        SendRspToClient(req, rspCode, NULL, 0);
        return;
    }
    Logger(DEBUG, MD_NM_SVR_HBM, "GetHbmNodeResetCap succeed. supported:%d", *supported);
    SendRspToClient(req, rspCode, (char *)supported, sizeof(int));
    free(supported);
}

static int EnsureCacheDriver(HbmTask *task)
{
    if (SetHbmTaskPhase(task, "check_cache_nodes", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    // Check if kernel module exist
    FILE *checkFile = popen("find /sys/kernel/hbm_cache/*/state -type f", "r");
    if (checkFile == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to run find command");
        return PWR_ERR_COMMON;
    }

    if (fgetc(checkFile) == EOF) {
        Logger(INFO, MD_NM_SVR_HBM, "No hbm_cache state files found, loading kernel moudle");
        if (SetHbmTaskPhase(task, "load_cache_driver", NULL, NULL) != PWR_SUCCESS) {
            pclose(checkFile);
            return PWR_ERR_HBM_OPERATION_TIMEOUT;
        }
        if (system("modprobe hisi_hbmcache") != 0) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to load hbm.ko module");
            pclose(checkFile);
            return PWR_ERR_COMMON;
        }
    }
    pclose(checkFile);
    return PWR_SUCCESS;
}

static int SetCacheDeviceState(HbmTask *task, const char *stateStr)
{
    long long stepStartUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase start. phase:set_cache_state, state:%s", stateStr);
    if (SetHbmTaskPhase(task, "set_cache_state", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int commandRet = SetStateFiles(task, HBM_CACHE_STATE_PATTERN, stateStr, "Failed to set hbm cache state");
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:set_cache_state, state:%s, ret:%d, durationUs:%lld",
        stateStr, commandRet, GetTimeUs() - stepStartUs);
    // Preserve status polling after ordinary write failures; stop immediately on timeout.
    return IsHbmTaskTimedOut(task) ? PWR_ERR_HBM_OPERATION_TIMEOUT : PWR_SUCCESS;
}

static int WaitCacheDeviceState(HbmTask *task, int powerState)
{
    // check status
    const char *checkCmd;
    if (powerState == 0) {
        checkCmd =
            "find /sys/kernel/hbm_cache/*/firmware_node/status -type f | "
            "xargs -I {} cat {} 2>/dev/null | grep -q -x -v "
            "'0' && echo \"Failure\" || echo \"Success\"";
    } else {
        checkCmd =
            "find /sys/kernel/hbm_cache/*/firmware_node/status -type f | "
            "xargs -I {} cat {} 2>/dev/null | grep -q -x -v "
            "'15' && echo \"Failure\" || echo \"Success\"";
    }

    if (SetHbmTaskPhase(task, "wait_cache_state", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int retryCount = 0;
    while (retryCount < MAX_RETRY_COUNT) {
        if (IsHbmTaskTimedOut(task)) {
            return PWR_ERR_HBM_OPERATION_TIMEOUT;
        }
        FILE *fp = popen(checkCmd, "r");
        if (fp == NULL) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to run command");
            return PWR_ERR_COMMON;
        }

        char result[PWR_MAX_NAME_LEN];
        if (fgets(result, sizeof(result), fp) != NULL) {
            if (strncmp(result, "Success", strlen("Success")) == 0) {
                pclose(fp);
                return PWR_SUCCESS;
            }
        }
        pclose(fp);

        usleep(RETRY_INTERVAL_MS * MICROSECONDS_PER_MILLISECOND);
        retryCount++;
    }

    Logger(ERROR, MD_NM_SVR_HBM, "HBM target power state not confirmed after %d checks", retryCount);
    return PWR_ERR_HBM_POWER_STATE_NOT_REACHED;
}

static int HandleCacheMode(HbmTask *task, const int powerState)
{
    int ret = EnsureCacheDriver(task);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    const char *stateStr = (powerState == 0) ? "offline" : "online";
    ret = SetCacheDeviceState(task, stateStr);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    return WaitCacheDeviceState(task, powerState);
}

static int EnsureFlatDriver(HbmTask *task, const char *stateStr)
{
    // Check if kernel module exist
    long long stepStartUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM, "HBM phase start. phase:check_device_nodes, state:%s", stateStr);
    FILE *checkFile = popen("find /sys/devices/system/container/PNP0A06*/state -type f", "r");
    if (checkFile == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to run find command");
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM phase finish. phase:check_device_nodes, state:%s, ret:%d, durationUs:%lld",
            stateStr, PWR_ERR_COMMON, GetTimeUs() - stepStartUs);
        return PWR_ERR_COMMON;
    }

    if (fgetc(checkFile) == EOF) {
        Logger(INFO, MD_NM_SVR_HBM, "No hbm_cache state files found, loading kernel moudle");
        Logger(DEBUG, MD_NM_SVR_HBM, "HBM driver load start. module:hisi_hbmdev");
        long long loadStartUs = GetTimeUs();
        if (SetHbmTaskPhase(task, "load_device_driver", NULL, NULL) != PWR_SUCCESS) {
            pclose(checkFile);
            return PWR_ERR_HBM_OPERATION_TIMEOUT;
        }
        if (system("modprobe hisi_hbmdev") != 0) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to load hbm.ko module");
            Logger(DEBUG, MD_NM_SVR_HBM,
                "HBM driver load finish. module:hisi_hbmdev, ret:%d, durationUs:%lld",
                PWR_ERR_COMMON, GetTimeUs() - loadStartUs);
            pclose(checkFile);
            Logger(DEBUG, MD_NM_SVR_HBM,
                "HBM phase finish. phase:check_device_nodes, state:%s, ret:%d, durationUs:%lld",
                stateStr, PWR_ERR_COMMON, GetTimeUs() - stepStartUs);
            return PWR_ERR_COMMON;
        }
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM driver load finish. module:hisi_hbmdev, ret:%d, durationUs:%lld",
            PWR_SUCCESS, GetTimeUs() - loadStartUs);
    }
    pclose(checkFile);
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:check_device_nodes, state:%s, ret:%d, durationUs:%lld",
        stateStr, PWR_SUCCESS, GetTimeUs() - stepStartUs);
    return PWR_SUCCESS;
}

static int CheckFlatDevicesOffline(HbmTask *task, int *allOffline)
{
    glob_t paths = {0};
    *allOffline = 0;
    if (glob(HBM_DEVICE_STATUS_PATTERN, GLOB_NOSORT, NULL, &paths) != 0 || paths.gl_pathc == 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Cannot verify HBM device state when no memory nodes were offlined");
        globfree(&paths);
        return PWR_ERR_HBM_SET_POWER_STATE_FAILED;
    }

    int ret = PWR_SUCCESS;
    int offlineCount = 0;
    for (size_t i = 0; i < paths.gl_pathc; i++) {
        if (IsHbmTaskTimedOut(task)) {
            ret = PWR_ERR_HBM_OPERATION_TIMEOUT;
            break;
        }
        char status[PWR_MAX_NAME_LEN] = {0};
        if (ReadFile(paths.gl_pathv[i], status, sizeof(status)) != PWR_SUCCESS) {
            ret = PWR_ERR_HBM_SET_POWER_STATE_FAILED;
            break;
        }
        if (strcmp(status, "13") == 0) {
            offlineCount++;
        } else if (strcmp(status, "15") != 0) {
            Logger(ERROR, MD_NM_SVR_HBM, "Unexpected HBM device status %s at %s", status, paths.gl_pathv[i]);
            ret = PWR_ERR_HBM_SET_POWER_STATE_FAILED;
            break;
        }
    }
    if (ret == PWR_SUCCESS) {
        if (offlineCount == (int)paths.gl_pathc) {
            *allOffline = 1;
        } else {
            Logger(ERROR, MD_NM_SVR_HBM,
                "No HBM memory nodes were offlined, but %zu of %zu devices remain online",
                paths.gl_pathc - offlineCount, paths.gl_pathc);
            ret = PWR_ERR_HBM_OFFLINE_MEMORY_FAILED;
        }
    }
    globfree(&paths);
    return ret;
}

static int PrepareFlatPowerOff(HbmTask *task, int *alreadyOffline)
{
    int offlinedCnt = 0;
    // Flush cache after HBM memory is offlined and before the device is powered off.
    int offlineRet = OfflineAllHBMNode(task, &offlinedCnt);
    if (offlineRet != PWR_SUCCESS) {
        return offlineRet;
    }
    if (offlinedCnt == 0) {
        int ret = CheckFlatDevicesOffline(task, alreadyOffline);
        if (ret == PWR_SUCCESS) {
            Logger(INFO, MD_NM_SVR_HBM, "HBM devices already offline; skipping repeated power-off and flush");
        }
        return ret;
    }
    if (GetHbmFlushEnable() == 0) {
        Logger(WARNING, MD_NM_SVR_HBM,
            "HBM flush disabled by hbm_flush_enable=0, skip cache flush before power-off");
        return PWR_SUCCESS;
    }
    return FlushHbmCacheBeforePowerOff(task);
}

static int SetFlatDeviceState(HbmTask *task, const char *stateStr)
{
    // online/offline hbm node
    long long stepStartUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase start. phase:set_device_state, state:%s", stateStr);
    if (SetHbmTaskPhase(task, "set_device_state", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int commandRet = SetStateFiles(task, HBM_DEVICE_STATE_PATTERN, stateStr, "Failed to set hbm device state");
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:set_device_state, state:%s, ret:%d, durationUs:%lld",
        stateStr, commandRet, GetTimeUs() - stepStartUs);
    // Preserve status polling after ordinary write failures; stop immediately on timeout.
    return IsHbmTaskTimedOut(task) ? PWR_ERR_HBM_OPERATION_TIMEOUT : PWR_SUCCESS;
}

static int WaitFlatDeviceState(HbmTask *task, int powerState, const char *stateStr)
{
    // check if online/offline is successful
    const char *checkCmd;
    if (powerState == 0) {
        checkCmd =
            "find /sys/devices/system/container/PNP0A06*/firmware_node/PNP0C80*/status -type f | xargs -I {} cat {} "
            "2>/dev/null | grep -q -x -v '13' && echo \"Failure\" || echo \"Success\"";
    } else {
        checkCmd =
            "find /sys/devices/system/container/PNP0A06*/firmware_node/PNP0C80*/status -type f | xargs -I {} cat {} "
            "2>/dev/null | grep -q -x -v '15' && echo \"Failure\" || echo \"Success\"";
    }

    if (SetHbmTaskPhase(task, "wait_device_state", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    int retryCount = 0;
    long long stepStartUs = GetTimeUs();
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase start. phase:wait_device_state, state:%s", stateStr);
    while (retryCount < MAX_RETRY_COUNT) {
        if (IsHbmTaskTimedOut(task)) {
            return PWR_ERR_HBM_OPERATION_TIMEOUT;
        }
        FILE *fp = popen(checkCmd, "r");
        if (fp == NULL) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to check hbm power state");
            Logger(DEBUG, MD_NM_SVR_HBM,
                "HBM phase finish. phase:wait_device_state, state:%s, ret:%d, retryCount:%d, durationUs:%lld",
                stateStr, PWR_ERR_COMMON, retryCount, GetTimeUs() - stepStartUs);
            return PWR_ERR_COMMON;
        }

        char result[PWR_MAX_NAME_LEN];
        if (fgets(result, sizeof(result), fp) != NULL) {
            if (strncmp(result, "Success", strlen("Success")) == 0) {
                pclose(fp);
                Logger(DEBUG, MD_NM_SVR_HBM,
                    "HBM phase finish. phase:wait_device_state, state:%s, ret:%d, retryCount:%d, durationUs:%lld",
                    stateStr, PWR_SUCCESS, retryCount, GetTimeUs() - stepStartUs);
                return PWR_SUCCESS;
            }
        }
        pclose(fp);

        usleep(RETRY_INTERVAL_MS * MICROSECONDS_PER_MILLISECOND);
        retryCount++;
    }

    Logger(ERROR, MD_NM_SVR_HBM, "HBM target power state not confirmed after %d checks", retryCount);
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:wait_device_state, state:%s, ret:%d, retryCount:%d, durationUs:%lld",
        stateStr, PWR_ERR_HBM_POWER_STATE_NOT_REACHED, retryCount, GetTimeUs() - stepStartUs);
    return PWR_ERR_HBM_POWER_STATE_NOT_REACHED;
}

static int HandleFlatMode(HbmTask *task, const int powerState)
{
    if (SetHbmTaskPhase(task, "check_device_nodes", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    long long phaseStartUs = GetTimeUs();
    const char *stateStr = (powerState == 0) ? "offline" : "online";
    Logger(DEBUG, MD_NM_SVR_HBM, "HBM flat operation start. state:%s", stateStr);

    int ret = EnsureFlatDriver(task, stateStr);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    int alreadyOffline = 0;
    if (powerState == 0) {
        ret = PrepareFlatPowerOff(task, &alreadyOffline);
    }
    if (ret == PWR_SUCCESS && !alreadyOffline) {
        ret = SetFlatDeviceState(task, stateStr);
    }
    if (ret == PWR_SUCCESS && !alreadyOffline) {
        ret = WaitFlatDeviceState(task, powerState, stateStr);
    }
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM flat operation finish. state:%s, ret:%d, durationUs:%lld",
        stateStr, ret, GetTimeUs() - phaseStartUs);
    return ret;
}

static int SetPowerState(HbmTask *task, int powerState)
{
    if (SetHbmTaskPhase(task, "detect_mode", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    long long startUs = GetTimeUs();
    PWR_HBM_SYS_STATE hbmState = PWR_HBM_NOT_SUPPORT;
    int ret = PWR_ERR_HBM_SET_POWER_STATE_FAILED;
    Logger(DEBUG, MD_NM_SVR_HBM, "HBM phase start. phase:detect_mode, requestedState:%d", powerState);
    int modeRet = GetHbmMode(&hbmState);
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM phase finish. phase:detect_mode, requestedState:%d, mode:%d, ret:%d, durationUs:%lld",
        powerState, hbmState, modeRet, GetTimeUs() - startUs);
    if (modeRet != PWR_SUCCESS || hbmState == PWR_HBM_NOT_SUPPORT) {
        Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: HBM is not support");
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }

    if (hbmState == PWR_HBM_CACHE_MOD) {
        ret = HandleCacheMode(task, powerState);
    } else if (hbmState == PWR_HBM_FLAT_MOD) {
        ret = HandleFlatMode(task, powerState);
    }

    return ret;
}

int ExecuteHbmPowerTask(HbmTask *task)
{
    if (!task) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    int ret = StartHbmTask(task);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    if (SetHbmTaskPhase(task, "validate_request", NULL, NULL) != PWR_SUCCESS) {
        return PWR_ERR_HBM_OPERATION_TIMEOUT;
    }
    HbmTaskSnapshot snapshot;
    ret = SnapshotHbmTask(task, &snapshot);
    if (ret == PWR_SUCCESS) {
        int state = snapshot.powerState;
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM task execute. opt:%u, sysId:%u, seqId:%u, state:%d",
            snapshot.request.optType, snapshot.request.sysId, snapshot.request.seqId, state);
        FreeHbmTaskSnapshot(&snapshot);
        ret = (state == PWR_ENABLE || state == PWR_DISABLE) ?
            SetPowerState(task, state) : PWR_ERR_INVALIDE_PARAM;
    }
    FinishHbmTask(task, ret);
    return IsHbmTaskTimedOut(task) ? PWR_ERR_HBM_OPERATION_TIMEOUT : ret;
}

void SetHbmAllPowerState(PwrMsg *req)
{
    long long startUs = GetTimeUs();
    int rspCode = PWR_SUCCESS;
    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM request start. sysId:%d, seqId:%d, dataLen:%d",
        req ? req->head.sysId : 0, req ? req->head.seqId : 0, req ? req->head.dataLen : 0);
    do {
        if (!req || !req->data || req->head.dataLen != sizeof(int)) {
            Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: wrong req msg.dataLen:%d",
                   req ? req->head.dataLen : 0);
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }

        int state = *(const int *)req->data;
        if (state != PWR_ENABLE && state != PWR_DISABLE) {
            Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: wrong state:%d", state);
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }

        HbmTask *task = CreateHbmTask(req);
        if (!task) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to allocate HBM task context");
            rspCode = PWR_ERR_COMMON;
            break;
        }
        rspCode = ExecuteHbmPowerTask(task);
        // Synchronous owner for now. Future workers must wait for all readers before destruction.
        DestroyHbmTask(task);
    } while (PWR_FALSE);

    Logger(DEBUG, MD_NM_SVR_HBM,
        "HBM request finish. sysId:%d, seqId:%d, rspCode:%d, durationUs:%lld",
        req ? req->head.sysId : 0, req ? req->head.seqId : 0, rspCode, GetTimeUs() - startUs);
    SendRspToClient(req, rspCode, NULL, 0);
}
