/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wuhaotian
 * Create: 2022-11-10
 * Description: provide cpu service
 * **************************************************************************** */

#include "cpuservice.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "cpuservice.h"

static int PowerSet(char *powerState)
{
    FILE *fp = NULL;
    char *stateStr = malloc(strlen(powerState) + MAX_NAME_LEN);
    if (stateStr == NULL) {
        Logger(ERROR, MD_NM_SVR_SYS, "Malloc failed.");
        return 1;
    }
    static const char s1[] = "sleep 10 && echo ";
    static const char s2[] = "> /sys/power/state &";
    StrCopy(stateStr, s1, strlen(powerState) + MAX_NAME_LEN);
    strncat(stateStr, powerState, strlen(powerState));
    strncat(stateStr, s2, strlen(s2));
    fp = popen(stateStr, "r");
    if (fp == NULL) {
        return 1;
    }
    pclose(fp);
    return SUCCESS;
}

static int IpmiRead(const char *componentInfo, double *result)
{
    FILE *fp = NULL;
    fp = popen(componentInfo, "r");
    if (fp == NULL) {
        return ERR_COMMON;
    }
    char buf[MAX_STRING_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        return ERR_COMMON;
    }
    DeleteChar(buf, '\n');
    DeleteChar(buf, ' ');
    *result = atof(buf);
    pclose(fp);
    return SUCCESS;
}

static int SysRtPowerRead(PWR_SYS_PowerInfo *rstData)
{
    static const char sysPowerInfo[] =
        "printf \"%d\" 0x$(ipmitool raw 0x30 0x93 0xdb 0x07 0x00 0x11 0x0 | awk \'{print $7$6$5$4}\')";
    static const char cpuPowerInfo[] =
        "printf \"%d\" 0x$(ipmitool raw 0x30 0x93 0xdb 0x07 0x00 0x11 0x4 | awk \'{print $5$4}\')";
    static const char memPowerInfo[] =
        "printf \"%d\" 0x$(ipmitool raw 0x30 0x93 0xdb 0x07 0x00 0x11 0x5 | awk \'{print $5$4}\')";
    double sysPower;
    if (IpmiRead(sysPowerInfo, &sysPower)) {
        return ERR_COMMON;
    }
    rstData->sysPower = sysPower;
    if (GetArch() == 1) {
        double cpuPower, memPower;
        if (IpmiRead(cpuPowerInfo, &cpuPower) || IpmiRead(memPowerInfo, &memPower)) {
            return ERR_COMMON;
        }
        rstData->cpuPower = cpuPower;
        rstData->memPower = memPower;
    }
    return SUCCESS;
}

void SetSysPowerState(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_SYS, "Set Sys Power State Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    int rspCode = PowerSet(req->data);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_SYS, "Malloc failed.");
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, NULL, 0);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void GetSysRtPowerInfo(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_SYS, "Get Get Sys Rt Power Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    PWR_SYS_PowerInfo *rstData = malloc(sizeof(PWR_SYS_PowerInfo));
    if (!rstData) {
        return;
    }
    rstData->cpuPower = 0.0;
    rstData->memPower = 0.0;
    int rspCode = SysRtPowerRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_SYS_PowerInfo));
}
