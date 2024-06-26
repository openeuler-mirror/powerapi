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
 * Description: provide sys service
 * **************************************************************************** */

#include "sysservice.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "cpuservice.h"

static int PowerSet(char *powerState)
{
    int bufferTime = 10; // The value may need to be determined again
    static const char fileName[] = "/sys/power/state";

    sleep(bufferTime);
    int ret = WriteFile(fileName, powerState, strlen(powerState));
    if (ret != 0) {
        return ret;
    }
    return PWR_SUCCESS;
}

static int IpmiRead(const char *componentInfo, double *result)
{
    FILE *fp = NULL;
    fp = popen(componentInfo, "r");
    if (fp == NULL) {
        return PWR_ERR_COMMON;
    }
    char buf[PWR_MAX_STRING_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        return PWR_ERR_COMMON;
    }
    DeleteChar(buf, '\n');
    DeleteChar(buf, ' ');
    *result = atof(buf);
    pclose(fp);
    return PWR_SUCCESS;
}

static int SysRtPowerRead(PWR_SYS_PowerInfo *rstData)
{
    static const char sysPowerInfo[] =
        "printf \"%d\" 0x$(ipmitool raw 0x30 0x93 0xdb 0x07 0x00 0x11 0x0 | awk \'{print $7$6$5$4}\')";
    static const char cpuPowerInfo[] =
        "printf \"%d\" 0x$(ipmitool raw 0x30 0x93 0xdb 0x07 0x00 0x11 0x4 | awk \'{print $5$4}\')";
    static const char memPowerInfo[] =
        "printf \"%d\" 0x$(ipmitool raw 0x30 0x93 0xdb 0x07 0x00 0x11 0x5 | awk \'{print $5$4}\')";
    double value = 0;
    if (IpmiRead(sysPowerInfo, &value)) {
        return PWR_ERR_COMMON;
    }
    rstData->sysPower = value;

    value = 0;
    if (IpmiRead(cpuPowerInfo, &value) == PWR_SUCCESS) {
        rstData->cpuPower = value;
    }

    value = 0;
    if (IpmiRead(memPowerInfo, &value) == PWR_SUCCESS) {
        rstData->memPower = value;
    }
    return PWR_SUCCESS;
}

// public===========================================================================================
void SetSysPowerState(PwrMsg *req)
{
    int rspCode = PowerSet(req->data);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_SYS, "Malloc failed.");
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, NULL, 0);
    if (SendRspMsg(rsp) != PWR_SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void GetSysRtPowerInfo(PwrMsg *req)
{
    PWR_SYS_PowerInfo *rstData = malloc(sizeof(PWR_SYS_PowerInfo));
    if (!rstData) {
        return;
    }
    rstData->cpuPower = 0.0;
    rstData->memPower = 0.0;
    int rspCode = SysRtPowerRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_SYS_PowerInfo));
}