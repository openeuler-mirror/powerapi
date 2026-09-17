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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include "config.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "hbmservice.h"

#define MAX_RETRY_COUNT 50
#define RETRY_INTERVAL_MS 100
#define MAX_HBM_NODE_COUNT 256
#define HBM_FLUSH_MODULE_NAME "hbm_flush"
#define HBM_FLUSH_PROC_PATH "/proc/hbm_flush"
#define HBM_FLUSH_TRIGGER "1\n"
#define HBM_INSMOD_PATH "/sbin/insmod"

#define EXEC_COMMAND(cmd) \
    do { \
        FILE *fp = popen(cmd, "r"); \
        if (fp == NULL) { \
            return PWR_ERR_COMMON; \
        } \
        pclose(fp); \
    } while (0)

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

static int CopyString(char *dest, size_t destSize, const char *src)
{
    if (!dest || destSize == 0 || !src) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    size_t i = 0;
    while (src[i] != '\0') {
        if (i + 1 >= destSize) {
            dest[0] = '\0';
            return PWR_ERR_COMMON;
        }
        dest[i] = src[i];
        ++i;
    }
    dest[i] = '\0';
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
        _exit(127);
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

    return ret;
}

static int SetMemoryState(const char *nodePath, const char *state)
{
    char memoryStateFile[MAX_FULL_NAME];
    char currentState[PWR_MAX_NAME_LEN] = {0};
    DIR *dir;
    struct dirent *entry;

    dir = opendir(nodePath);
    if (dir == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open memory directory");
        return PWR_ERR_COMMON;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "memory", strlen("memory")) != 0) {
            continue;
        }

        int ret = BuildPath(memoryStateFile, sizeof(memoryStateFile), nodePath, entry->d_name, "state");
        if (ret != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Buffer overflow detected in memoryStateFile");
            continue;
        }

        if (ReadFile(memoryStateFile, currentState, sizeof(currentState)) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to read memory state file %s", memoryStateFile);
            closedir(dir);
            return PWR_ERR_COMMON;
        }

        if (strcmp(currentState, state) == 0) {
            continue;
        }

        // Check each block immediately before offlining; online rollback must not be gated by removable.
        if (strcmp(state, "offline") == 0 && CheckMemoryRemovable(nodePath, entry->d_name) != PWR_SUCCESS) {
            closedir(dir);
            return PWR_ERR_COMMON;
        }

        if (WriteFile(memoryStateFile, state, strlen(state)) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to write %s to memory state file %s", state, memoryStateFile);
            closedir(dir);
            return PWR_ERR_COMMON;
        }
    }

    closedir(dir);
    return PWR_SUCCESS;
}

static int OfflineMemoryState(const char *nodePath)
{
    return SetMemoryState(nodePath, "offline");
}

static int OnlineMemoryState(const char *nodePath)
{
    return SetMemoryState(nodePath, "online");
}

// Try to bring back every previously-offlined node. Keep going even if one fails
// so we minimize the damage, but report the overall result to the caller so a
// partial/inconsistent state is never hidden.
static int RevertOfflinedNodes(char offlinedNodes[][MAX_FULL_NAME], int count)
{
    int revertErr = PWR_SUCCESS;
    for (int i = count - 1; i >= 0; --i) {
        if (OnlineMemoryState(offlinedNodes[i]) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to revert memory state of node %s", offlinedNodes[i]);
            revertErr = PWR_ERR_HBM_REVERT_MEMORY_FAILED;
        }
    }
    return revertErr;
}

static int OfflineAllHBMNode(char offlinedNodes[][MAX_FULL_NAME], int *offlinedCnt)
{
    DIR *dirPtr = opendir("/sys/devices/system/node");
    if (dirPtr == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open /sys/devices/system/node dir");
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

        if (!IsNodeEmptyCpuList(nodePath)) {
            continue;
        }

        if (*offlinedCnt >= MAX_HBM_NODE_COUNT) {
            Logger(ERROR, MD_NM_SVR_HBM, "HBM node count exceeds max revert capacity %d", MAX_HBM_NODE_COUNT);
            errCode = PWR_ERR_COMMON;
            break;
        }

        // Record the node path before offlining so a partial failure inside the
        // node is also covered by the revert loop (OnlineMemoryState is idempotent).
        if (CopyString(offlinedNodes[*offlinedCnt], MAX_FULL_NAME, nodePath) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to save offlined node path %s", nodePath);
            errCode = PWR_ERR_COMMON;
            break;
        }
        (*offlinedCnt)++;

        if (OfflineMemoryState(nodePath) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to offline memory of node %s", nodePath);
            errCode = PWR_ERR_HBM_OFFLINE_MEMORY_FAILED;
            break;
        }
    }

    closedir(dirPtr);

    if (errCode != PWR_SUCCESS) {
        // If revert itself fails, the system is left in a half-offlined state;
        // surface the stronger error so callers don't treat it as a clean failure.
        int revertErr = RevertOfflinedNodes(offlinedNodes, *offlinedCnt);
        if (revertErr != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM,
                   "HBM offline revert failed, system left in inconsistent state (offlined=%d)",
                   *offlinedCnt);
            errCode = revertErr;
        }
    }

    return errCode;
}

static int RevertOfflinedNodesOnError(char offlinedNodes[][MAX_FULL_NAME], int offlinedCnt, int errCode)
{
    int revertErr = RevertOfflinedNodes(offlinedNodes, offlinedCnt);
    if (revertErr != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM,
               "Failed to revert HBM memory nodes after error:%d, offlined:%d",
               errCode, offlinedCnt);
        return revertErr;
    }
    return errCode;
}

static int LoadHbmFlushModule(int *needUnload)
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
    if (RunInsmod(modulePath) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to insmod %s", modulePath);
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
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

static int TriggerHbmCacheFlush(void)
{
    int fd = open(HBM_FLUSH_PROC_PATH, O_WRONLY);
    if (fd < 0) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open %s. errno:%d, %s",
               HBM_FLUSH_PROC_PATH, errno, strerror(errno));
        return PWR_ERR_HBM_FLUSH_CACHE_FAILED;
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

static int FlushHbmCacheBeforePowerOff(void)
{
    int needUnload = 0;
    int ret = LoadHbmFlushModule(&needUnload);
    if (ret == PWR_SUCCESS) {
        ret = TriggerHbmCacheFlush();
    }

    int unloadRet = needUnload ? UnloadHbmFlushModule() : PWR_SUCCESS;
    if (ret != PWR_SUCCESS) {
        return ret;
    }

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

static int HandleCacheMode(const int powerState)
{
    char cmd[PWR_MAX_STRING_LEN] = {0};
    const char *stateStr = (powerState == 0) ? "offline" : "online";

    // Check if kernel module exist
    FILE *checkFile = popen("find /sys/kernel/hbm_cache/*/state -type f", "r");
    if (checkFile == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to run find command");
        return PWR_ERR_COMMON;
    }

    if (fgetc(checkFile) == EOF) {
        Logger(INFO, MD_NM_SVR_HBM, "No hbm_cache state files found, loading kernel moudle");
        if (system("modprobe hisi_hbmcache") != 0) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to load hbm.ko module");
            pclose(checkFile);
            return PWR_ERR_COMMON;
        }
    }
    pclose(checkFile);

    snprintf(cmd, sizeof(cmd),
             "find /sys/kernel/hbm_cache/*/state -type f | xargs -I {} sh -c "
             "'echo \"%s\" > {}'",
             stateStr);
    EXEC_COMMAND(cmd);

    // check status
    const char *checkCmd;
    if (powerState == 0) {
        checkCmd =
            "find /sys/kernel/hbm_cache/*/firmware_node/status -type f | xargs -I {} cat {} 2>/dev/null | grep -q -v "
            "'0' && echo \"Failure\" || echo \"Success\"";
    } else {
        checkCmd =
            "find /sys/kernel/hbm_cache/*/firmware_node/status -type f | xargs -I {} cat {} 2>/dev/null | grep -q -v "
            "'15' && echo \"Failure\" || echo \"Success\"";
    }

    int retryCount = 0;
    while (retryCount < MAX_RETRY_COUNT) {
        FILE *fp = popen(checkCmd, "r");
        if (fp == NULL) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to run command");
            return PWR_ERR_COMMON;
        }

        char result[PWR_MAX_NAME_LEN];
        if (fgets(result, sizeof(result), fp) != NULL) {
            if (strncmp(result, "Success", 7) == 0) {
                pclose(fp);
                return PWR_SUCCESS;
            }
        }
        pclose(fp);

        usleep(RETRY_INTERVAL_MS * 1000);
        retryCount++;
    }

    Logger(ERROR, MD_NM_SVR_HBM, "Failed to set hbm power state after retries");
    return PWR_ERR_HBM_SET_POWER_STATE_FAILED;
}

static int HandleFlatMode(const int powerState)
{
    // Check if kernel module exist
    FILE *checkFile = popen("find /sys/devices/system/container/PNP0A06*/state -type f", "r");
    if (checkFile == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to run find command");
        return PWR_ERR_COMMON;
    }

    if (fgetc(checkFile) == EOF) {
        Logger(INFO, MD_NM_SVR_HBM, "No hbm_cache state files found, loading kernel moudle");
        if (system("modprobe hisi_hbmdev") != 0) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to load hbm.ko module");
            pclose(checkFile);
            return PWR_ERR_COMMON;
        }
    }
    pclose(checkFile);

    char offlinedNodes[MAX_HBM_NODE_COUNT][MAX_FULL_NAME] = {0};
    int offlinedCnt = 0;

    // Flush cache after HBM memory is offlined and before the device is powered off.
    if (powerState == 0) {
        int offlineRet = OfflineAllHBMNode(offlinedNodes, &offlinedCnt);
        if (offlineRet != PWR_SUCCESS) {
            return offlineRet;
        }

        int flushRet = FlushHbmCacheBeforePowerOff();
        if (flushRet != PWR_SUCCESS) {
            return RevertOfflinedNodesOnError(offlinedNodes, offlinedCnt, flushRet);
        }
    }

    // online/offline hbm node
    const char *stateStr = (powerState == 0) ? "offline" : "online";
    char cmd[PWR_MAX_STRING_LEN] = {0};
    snprintf(cmd, sizeof(cmd),
             "find /sys/devices/system/container/PNP0A06*/state -type f | xargs -I {} sh -c 'echo "
             "\"%s\" > {}'",
             stateStr);
    EXEC_COMMAND(cmd);

    // check if online/offline is successful
    const char *checkCmd;
    if (powerState == 0) {
        checkCmd =
            "find /sys/devices/system/container/PNP0A06*/firmware_node/PNP0C80*/status -type f | xargs -I {} cat {} "
            "2>/dev/null | grep -q -v '13' && echo \"Failure\" || echo \"Success\"";
    } else {
        checkCmd =
            "find /sys/devices/system/container/PNP0A06*/firmware_node/PNP0C80*/status -type f | xargs -I {} cat {} "
            "2>/dev/null | grep -q -v '15' && echo \"Failure\" || echo \"Success\"";
    }

    int retryCount = 0;
    while (retryCount < MAX_RETRY_COUNT) {
        FILE *fp = popen(checkCmd, "r");
        if (fp == NULL) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to check hbm power state");
            return PWR_ERR_COMMON;
        }

        char result[PWR_MAX_NAME_LEN];
        if (fgets(result, sizeof(result), fp) != NULL) {
            if (strncmp(result, "Success", 7) == 0) {
                pclose(fp);
                return PWR_SUCCESS;
            }
        }
        pclose(fp);

        usleep(RETRY_INTERVAL_MS * 1000); // 转换为微秒
        retryCount++;
    }

    Logger(ERROR, MD_NM_SVR_HBM, "Failed to set hbm power state after retries");
    return PWR_ERR_HBM_SET_POWER_STATE_FAILED;
}

static int SetPowerState(int powerState)
{
    PWR_HBM_SYS_STATE hbmState = PWR_HBM_NOT_SUPPORT;
    int ret = PWR_ERR_HBM_SET_POWER_STATE_FAILED;
    if (GetHbmMode(&hbmState) != PWR_SUCCESS || hbmState == PWR_HBM_NOT_SUPPORT) {
        Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: HBM is not support");
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }

    if (hbmState == PWR_HBM_CACHE_MOD) {
        ret = HandleCacheMode(powerState);
    } else if (hbmState == PWR_HBM_FLAT_MOD) {
        ret = HandleFlatMode(powerState);
    }

    return ret;
}

void SetHbmAllPowerState(PwrMsg *req)
{
    int rspCode = PWR_SUCCESS;
    do {
        if (!req || req->head.dataLen != sizeof(int)) {
            Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: wrong req msg.dataLen:%d",
                   req->head.dataLen);
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }

        int state = *(int *)req->data;
        if (state != PWR_ENABLE && state != PWR_DISABLE) {
            Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: wrong state:%d", state);
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }

        rspCode = SetPowerState(state);
    } while (PWR_FALSE);

    SendRspToClient(req, rspCode, NULL, 0);
}
