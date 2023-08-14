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
 * Description: Provide service for PowerAPI refer to CPU.
 * **************************************************************************** */

#include "pwrcpu.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int GetCpuInfo(PWR_CPU_Info *cpuInfo)
{
    ReqInputParam input;
    input.optType = CPU_GET_INFO;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    size_t s = sizeof(PWR_CPU_Info);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)cpuInfo;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuInfo failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "GetCpuInfo succeed.");
    }
    return ret;
}

int GetCpuUsage(PWR_CPU_Usage *usage, uint32_t bufferSize)
{
    ReqInputParam input;
    input.optType = CPU_GET_USAGE;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    uint32_t size = bufferSize;
    output.rspBuffSize = &size;
    output.rspData = (void *)usage;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuUsage failed. ret: %d", ret);
        return ret;
    }

    // Remediate coreNum
    size_t coreNum = (size - sizeof(PWR_CPU_Usage)) / sizeof(PWR_CPU_CoreUsage);
    usage->coreNum = coreNum;
    PwrLog(DEBUG, "GetCpuUsage succeed.");
    return PWR_SUCCESS;
}

int GetCpuPerfData(PWR_CPU_PerfData *perfData)
{
    ReqInputParam input;
    input.optType = CPU_GET_PERF_DATA;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    size_t s = sizeof(PWR_CPU_PerfData);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)perfData;
    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuPerfData failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "GetCpuPerfData succeed.");
    }
    return ret;
}

int GetCpuFreqAbility(PWR_CPU_FreqAbility *freqAbi, uint32_t bufferSize)
{
    ReqInputParam input;
    input.optType = CPU_GET_FREQ_ABILITY;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    uint32_t size = bufferSize;
    output.rspBuffSize = &size;
    output.rspData = (void *)freqAbi;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuFreqAbility failed. ret: %d", ret);
        if (freqAbi->freqDomainStep != 0) {
            // Remediate the data to avoid error happens in buffersize is smaller then real data length.
            size_t freqDomainNum = (size - sizeof(PWR_CPU_FreqAbility)) / freqAbi->freqDomainStep;
            freqAbi->freqDomainNum = freqDomainNum;
        }
    } else {
        PwrLog(DEBUG, "GetCpuFreqAbility succeed.");
    }
    return ret;
}

int GetCpuFreqRange(PWR_CPU_FreqRange *freqRange)
{
    ReqInputParam input;
    input.optType = CPU_GET_FREQ_RANGE;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    size_t s = sizeof(PWR_CPU_FreqRange);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)freqRange;
    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuFreqRange failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "GetCpuFreqRange succeed.");
    }
    return ret;
}

int SetCpuFreqRange(const PWR_CPU_FreqRange *freqRange)
{
    ReqInputParam input;
    input.optType = CPU_SET_FREQ_RANGE;
    size_t dataLen = sizeof(PWR_CPU_FreqRange);
    input.dataLen = dataLen;
    input.data = (char *)freqRange;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetCpuFreqRange failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "SetCpuFreqRange succeed.");
    }
    return ret;
}

int GetCpuFreqGovernor(char gov[], uint32_t size)
{
    ReqInputParam input;
    input.optType = CPU_GET_FREQ_GOVERNOR;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    output.rspBuffSize = &size;
    output.rspData = (void *)gov;
    bzero(gov, size);
    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuFreqGovernor failed. ret: %d", ret);
        return ret;
    }

    if (gov[size - 1] != 0) {
        gov[size - 1] = 0;
        return PWR_ERR_ANSWER_LONGER_THAN_SIZE;
    }

    PwrLog(DEBUG, "GetCpuFreqGovernor succeed.");
    return ret;
}

int SetCpuFreqGovernor(const char gov[], uint32_t size)
{
    ReqInputParam input;
    input.optType = CPU_SET_FREQ_GOVERNOR;
    input.dataLen = size;
    input.data = (char *)gov;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetCpuFreqGovernor failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "SetCpuFreqGovernor succeed.");
    }
    return ret;
}

int GetCpuCurFreq(PWR_CPU_CurFreq curFreq[], uint32_t *num, int spec)
{
    if ((*num) > PWR_MAX_INPUT_NUM) {
        PwrLog(ERROR, "GetCpuCurFreq failed. ret: %d", PWR_ERR_INPUT_OVERSIZE);
        return PWR_ERR_INPUT_OVERSIZE;
    }
    size_t s = sizeof(PWR_CPU_CurFreq) * (*num);
    uint32_t size = s;
    ReqInputParam input;
    input.optType = CPU_GET_CUR_FREQ;
    if (spec) {
        input.dataLen = size;
        input.data = (char *)curFreq;
    } else {
        input.dataLen = 0;
        input.data = NULL;
    }

    RspOutputParam output;
    output.rspBuffSize = &size;
    output.rspData = (void *)curFreq;

    int ret = SendReqAndWaitForRsp(input, output);
    size_t curNum = size / sizeof(PWR_CPU_CurFreq);
    *num = curNum;
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuCurFreq failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "GetCpuCurFreq succeed.");
    }
    return ret;
}

int SetCpuCurFreq(const PWR_CPU_CurFreq curFreq[], uint32_t num)
{
    ReqInputParam input;
    input.optType = CPU_SET_CUR_FREQ;
    size_t dataLen = sizeof(PWR_CPU_CurFreq) * num;
    input.dataLen = dataLen;
    input.data = (char *)curFreq;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetCpuCurFreq failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "SetCpuCurFreq succeed.");
    }
    return ret;
}

int GetCpuDmaLatency(int *latency)
{
    ReqInputParam input;
    input.optType = CPU_GET_DMA_LATENCY;
    input.dataLen = 0;
    input.data = NULL;
    RspOutputParam output;
    size_t s = sizeof(int);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)latency;
    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetCpuDmaLatency failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "GetCpuDmaLatency succeed.");
    }
    return ret;
}

int SetCpuDmaLatency(int latency)
{
    ReqInputParam input;
    input.optType = CPU_SET_DMA_LATENCY;
    size_t dataLen = sizeof(int);
    input.dataLen = dataLen;
    input.data = (char *)&latency;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetCpuDmaLatency failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "SetCpuDmaLatency succeed.");
    }
    return ret;
}