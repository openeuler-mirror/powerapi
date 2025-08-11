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

#include "config.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "hbmservice.h"

#define MAX_RETRY_COUNT 50
#define RETRY_INTERVAL_MS 100

#define EXEC_COMMAND(cmd) \
    do { \
        FILE *fp = popen(cmd, "r"); \
        if (fp == NULL) { \
            return PWR_ERR_COMMON; \
        } \
        pclose(fp); \
    } while (0)

static int IsNodeEmptyCpuList(const char *nodePath)
{
    char cpuListFile[MAX_FULL_NAME];
    FILE *cpuListFp;
    char cpuListBuf[256];

    snprintf(cpuListFile, sizeof(cpuListFile), "%s/cpulist", nodePath);
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

static int OfflineMemoryState(const char *nodePath)
{
    char memoryDirPath[MAX_FULL_NAME];
    char memoryStateFile[MAX_FULL_NAME];
    DIR *dir;
    struct dirent *entry;

    snprintf(memoryDirPath, sizeof(memoryDirPath), "%s", nodePath);
    dir = opendir(memoryDirPath);
    if (dir == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open memory directory");
        return PWR_ERR_COMMON;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "memory", 6) != 0) {
            continue;
        }

        int ret = snprintf(memoryStateFile, sizeof(memoryStateFile), "%s/%s/state", memoryDirPath, entry->d_name);
        if (ret >= (int)sizeof(memoryStateFile)) {
            Logger(ERROR, MD_NM_SVR_HBM, "Buffer overflow detected in memoryStateFile");
            continue;
        }
        if (WriteFile(memoryStateFile, "offline", strlen("offline")) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_HBM, "Failed to write to memory state file");
            return PWR_ERR_COMMON;
        }
    }

    closedir(dir);
    return PWR_SUCCESS;
}

static int OfflineAllHBMNode()
{
    DIR *dirPtr;
    struct dirent *dirEntry;
    char nodePath[MAX_FULL_NAME];

    dirPtr = opendir("/sys/devices/system/node");
    if (dirPtr == NULL) {
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to open /sys/devices/system/node dir");
        return PWR_ERR_FILE_OPEN_FAILED;
    }

    while ((dirEntry = readdir(dirPtr)) != NULL) {
        if (strncmp(dirEntry->d_name, "node", 4) == 0) {
            snprintf(nodePath, sizeof(nodePath), "/sys/devices/system/node/%s", dirEntry->d_name);

            // if cpulist is empty, offline the node
            if (IsNodeEmptyCpuList(nodePath)) {
                if (OfflineMemoryState(nodePath) != PWR_SUCCESS) {
                    continue;
                }
            }
        }
    }

    closedir(dirPtr);
    return PWR_SUCCESS;
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

    // offline all memory
    if (powerState == 0) {
        if (OfflineAllHBMNode() != PWR_SUCCESS) {
            return PWR_ERR_COMMON;
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