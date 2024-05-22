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
 * Description: provide hbm operation interface
 * **************************************************************************** */

#include "pwrhbm.h"
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int GetHbmSysState(PWR_HBM_SYS_STATE *hmbState)
{
    ReqInputParam input;
    input.optType = HBM_GET_SYS_STATE;
    input.dataLen = 0;
    input.data = NULL;

    uint32_t size = sizeof(PWR_HBM_SYS_STATE);
    RspOutputParam output;
    output.rspBuffSize = &size;
    output.rspData = (void *)hmbState;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetHbmSysState failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "GetHbmSysState succeed.");
    }
    return ret;
}

int SetAllHbmPowerState(int state)
{
    ReqInputParam input;
    input.optType = HBM_SET_ALL_POWER_STATE;
    input.dataLen = sizeof(int);
    input.data = (char *)&state;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetAllHbmPowerState failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "SetAllHbmPowerState succeed.");
    }
    return ret;
}