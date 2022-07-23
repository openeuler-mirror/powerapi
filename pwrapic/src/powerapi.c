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
 * Author: queyanwen
 * Create: 2022-06-23
 * Description: PowerAPI interface implementation.
 * **************************************************************************** */

#include "powerapi.h"
#include <stdio.h>
#include <string.h>
#include "pwrlog.h"
#include "sockclient.h"
#include "pwrcpu.h"

static int g_registed = 0;

#define CHECK_STATUS() {                  \
    if (!g_registed) {                  \
        PwrLog(ERROR, "Not Registed."); \
        return ERR_NOT_REGISTED;        \
    }                                   \
}

#define CHECK_NULL_POINTER(p) {         \
    if (!(p)) {                         \
        return ERR_NULL_POINTER;        \
    }                                   \
}

static void DefaultLogCallback(int level, const char *fmt, va_list vl)
{
    printf(fmt);
}

void (*g_pwrlog_callback)(int level, const char *fmt, va_list vl) = DefaultLogCallback;

int PWR_SetLogCallback(void(LogCallback)(int, const char *, va_list))
{
    if (LogCallback) {
        g_pwrlog_callback = LogCallback;
        return 0;
    }
    return -1;
}

int PWR_Register()
{
    // todo: 增加必要的其他初始化动作
    if (InitSockClient() != SUCCESS) {
        return ERR_COMMON;
    }
    g_registed = 1;
    return SUCCESS;
}

int PWR_UnRegister()
{
    int ret = FiniSockClient();
    // todo: 增加必要的其他去初始化动作
    g_registed = 0;
    return ret;
}

int PWR_CPU_GetInfo(PWR_CPU_Info *cpuInfo)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(cpuInfo);

    return GetCpuInfo(cpuInfo);
}

int PWR_CPU_GetUsage(PWR_CPU_Usage *usage, uint32_t bufferSize)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(usage);

    if (bufferSize < sizeof(PWR_CPU_Usage)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetCpuUsage(usage, bufferSize);;
}

int PWR_CPU_GetFreqAbility(PWR_CPU_FreqAbility *freqAbi)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(freqAbi);

    return GetCpuFreqAbility(freqAbi);
}

int PWR_CPU_GetFreqGovernor(char gov[], uint32_t size)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(gov);
    if (size < MAX_ELEMENT_NAME_LEN) {
        return ERR_INVALIDE_PARAM;
    }

    return GetCpuFreqGovernor(gov, size);
}

int PWR_CPU_SetFreqGovernor(char gov[])
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(gov);
    if (strlen(gov) == 0 || strlen(gov) >= MAX_ELEMENT_NAME_LEN) {
        return ERR_INVALIDE_PARAM;
    }

    return SetCpuFreqGovernor(gov, strlen(gov) + 1);
}

int PWR_CPU_DmaGetLatency(int *latency)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(latency);

    return GetCpuDmaLatency(latency);
}

int PWR_CPU_DmaSetLatency(int latency)
{
    CHECK_STATUS();
    if (latency < 0 || latency > MAX_CPU_DMA_LATENCY) {
        return ERR_INVALIDE_PARAM;
    }

    return SetCpuDmaLatency(latency);
}
