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
 * Author: queyanwen
 * Create: 2022-06-23
 * Description: Provide service for PowerAPI refer to NET.
 * **************************************************************************** */

#include "pwrnet.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int GetNetInfo(PWR_NET_Info *netInfo, uint32_t bufferSize)
{
    ReqInputParam input;
    input.optType = NET_GET_INFO, input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    uint32_t size = bufferSize;
    output.rspBuffSize = &size;
    output.rspData = (void *)netInfo;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetNetInfo failed. ret:%d", ret);
        return ret;
    }

    // Remediate coreNum
    size_t ethNum = (size - sizeof(PWR_NET_Info)) / sizeof(PWR_NET_Eth);
    netInfo->ethNum = ethNum;
    PwrLog(DEBUG, "GetNetInfo succeed.");
    return PWR_SUCCESS;
}

int GetNetThrough(char ethName[], PWR_NET_Through *ethThrough)
{
    ReqInputParam input;
    input.optType = NET_GET_THROUGH;
    size_t dataLen = strlen(ethName) + 1;
    input.dataLen = dataLen;
    input.data = (char *)ethName;
    RspOutputParam output;
    size_t s = sizeof(PWR_NET_Through);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)ethThrough;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetNetThrough failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetNetThrough Succeed.");
    }
    return ret;
}

int GetNetSpeedMod(char ethName[], uint32_t *speedMod)
{
    ReqInputParam input;
    input.optType = NET_GET_SPEED_MOD;
    size_t dataLen = strlen(ethName) + 1;
    input.dataLen = dataLen;
    input.data = (char *)ethName;
    RspOutputParam output;
    size_t s = sizeof(uint32_t);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)speedMod;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetNetSpeedMod failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetNetSpeedMod Succeed.");
    }
    return ret;
}

int SetNetSpeedMod(char ethName[], uint32_t speedMod)
{
    ReqInputParam input = { 0 };
    input.optType = NET_SET_SPEED_MOD;
    size_t dlen = sizeof(speedMod) + strlen(ethName) + 1;
    input.dataLen = dlen;
    input.data = (char *)malloc(dlen);
    if (!input.data) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    bzero(input.data, dlen);
    memcpy(input.data, &speedMod, sizeof(speedMod));
    memcpy(input.data + sizeof(speedMod), ethName, strlen(ethName));

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetNetSpeedMod failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetNetSpeedMod Succeed.");
    }
    free(input.data);
    return ret;
}