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

#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "hbmservice.h"

#define EXEC_COMMAND(cmd) \
    do { \
        FILE *fp = popen(cmd, "r"); \
        if (fp == NULL) { \
            return PWR_ERR_COMMON; \
        } \
        pclose(fp); \
    } while (0)

static int GetHbmMode(PWR_HBM_SysState *state) 
{
    char cache_mod_cmd[] = "find /sys/devices/LNXSYSTM* -name 'HISI04A1*'";
    char flat_mod_cmd[] = "find /sys/devices/LNXSYSTM* -name 'PNP0C80*'";
    *state = PWR_HBM_NOT_SUPPORT;

    FILE *cache_mod_fp = popen(cache_mod_cmd, "r");
    if (cache_mod_fp == NULL) {
        return PWR_ERR_COMMON;
    }
    char cache_buf[PWR_MAX_STRING_LEN] = {0};
    if (fgets(cache_buf, PWR_MAX_STRING_LEN, cache_mod_fp) != NULL) {
        *state |= PWR_HBM_FLAT_MOD;
    }

    FILE *flat_mod_fp = popen(flat_mod_cmd, "r");
    if (flat_mod_fp == NULL) {
        pclose(cache_mod_fp);
        return PWR_ERR_COMMON;
    }
    char flat_buf[PWR_MAX_STRING_LEN] = {0};
    if (fgets(cache_buf, PWR_MAX_STRING_LEN, cache_mod_fp) != NULL) {
        *state |= PWR_HBM_CACHE_MOD;
    }
    pclose(cache_mod_fp);
    pclose(flat_mod_fp);
    return PWR_SUCCESS;
}

void GetHbmSysState(PwrMsg *req)
{
    PWR_HBM_SysState *state = (PWR_HBM_SysState *)malloc(sizeof(PWR_HBM_SysState));
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
        SendRspToClient(req, rspCode, (char *)state, sizeof(PWR_HBM_SysState));
    }
}

static int SetPowerState(int powerState)
{
    PWR_HBM_SysState hbmState = PWR_HBM_NOT_SUPPORT;
    if (GetHbmMode(&hbmState) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_HBM, "GetHbmMode failed");
        return PWR_ERR_COMMON;
    }
    if (hbmState == PWR_HBM_NOT_SUPPORT) {
        Logger(ERROR, MD_NM_SVR_HBM, "SetHbmAllPowerState: HBM is not support");
        return PWR_ERR_HBM_NOT_SUPPORTED;
    }

    const char *state_str = (powerState == 0) ? "offline" : "online";
    if (hbmState == PWR_HBM_CACHE_MOD || hbmState == PWR_HBM_HYBRID_MOD) {
        char cmd[PWR_MAX_STRING_LEN] = {0};
        snprintf(
            cmd, sizeof(cmd),
            "find /sys/kernel/hbm_cache/*/state -type f | xargs -I {} sh -c 'echo \"%s\" > {}'",
            state_str);
        EXEC_COMMAND(cmd);
    }

    if (hbmState == PWR_HBM_FLAT_MOD || hbmState == PWR_HBM_HYBRID_MOD) {
        char cmd[PWR_MAX_STRING_LEN] = {0};
        snprintf(cmd, sizeof(cmd),
                 "find /sys/devices/system/container/PNP0A06*/state -type f | xargs -I {} sh -c 'echo "
                 "\"%s\" > {}'",
                 state_str);
        EXEC_COMMAND(cmd);
    }
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