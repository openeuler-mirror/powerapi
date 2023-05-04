/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wuhaotian
 * Create: 2022-11-14
 * Description: Provide service for PowerAPI refer to SYS.
 * **************************************************************************** */

#include "pwrsys.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrdata.h"
#include "pwrerr.h"
#include "sockclient.h"

int SetSysPowerState(int powerState)
{
    ReqInputParam input;
    input.optType = SYS_SET_POWER_STATE;
    char state[MAX_NAME_LEN] = {0};
    if (powerState == MEM) {
        strncpy(state, "mem", strlen("mem"));
    } else if (powerState == DISK) {
        strncpy(state, "disk", strlen("disk"));
    }
    size_t dataLen = strlen(state);
    input.dataLen = dataLen;
    input.data = state;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != SUCCESS) {
        PwrLog(ERROR, "SetSysPowerState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetSysPowerState Succeed.");
    }
    return ret;
}


int GetSysRtPowerInfo(PWR_SYS_PowerInfo *powerInfo)
{
    ReqInputParam input;
    input.optType = SYS_GET_RT_POWER;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    size_t s = sizeof(PWR_SYS_PowerInfo);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)powerInfo;
    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != SUCCESS) {
        PwrLog(ERROR, "GetSysRtPower failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetSysRtPower Succeed.");
    }
    return ret;
}