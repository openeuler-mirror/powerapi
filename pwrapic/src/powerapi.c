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
#include "pwrdisk.h"
#include "pwrnet.h"
#include "pwrusb.h"

static int g_registed = 0;

#define CHECK_STATUS()                      \
    {                                       \
        if (!g_registed) {                  \
            PwrLog(ERROR, "Not Registed."); \
            return ERR_NOT_REGISTED;        \
        }                                   \
    }

#define CHECK_NULL_POINTER(p)        \
    {                                \
        if (!(p)) {                  \
            return ERR_NULL_POINTER; \
        }                            \
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

    return GetCpuUsage(usage, bufferSize);
    ;
}

int PWR_CPU_GetFreqAbility(PWR_CPU_FreqAbility *freqAbi, uint32_t bufferSize)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(freqAbi);
    if (bufferSize < sizeof(PWR_CPU_FreqAbility)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetCpuFreqAbility(freqAbi, bufferSize);
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

int PWR_CPU_GetFreq(PWR_CPU_CurFreq curFreq[], uint32_t *len, int spec)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(curFreq);
    if (!len || *len == 0 || (spec != TRUE && spec != FALSE)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetCpuCurFreq(curFreq, len, spec);
}

int PWR_CPU_SetFreq(PWR_CPU_CurFreq curFreq[], uint32_t len)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(curFreq);
    if (len == 0) {
        return ERR_INVALIDE_PARAM;
    }

    return SetCpuCurFreq(curFreq, len);
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


// Disk
int PWR_DISK_GetList(char diskList[][MAX_ELEMENT_NAME_LEN], uint32_t *len)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(diskList);
    if (!len || *len == 0) {
        return ERR_INVALIDE_PARAM;
    }

    return GetDiskList(diskList, len);
}

int PWR_DISK_GetLoad(PWR_DISK_Load load[], uint32_t *len, int spec)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(load);
    if (!len || *len == 0 || (spec != TRUE && spec != FALSE)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetDiskLoad(load, len, spec);
}

int PWR_DISK_GetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t *len, int spec)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(pwrLevel);
    if (!len || *len == 0 || (spec != TRUE && spec != FALSE)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetDiskPwrLevel(pwrLevel, len, spec);
}

int PWR_DISK_SetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t len)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(pwrLevel);
    if (len == 0) {
        return ERR_INVALIDE_PARAM;
    }

    return SetDiskPwrLevel(pwrLevel, len);
}

int PWR_DISK_GetScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t *len, int spec)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(scsiPolicy);
    if (!len || *len == 0 || (spec != TRUE && spec != FALSE)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetDiskScsiPolicy(scsiPolicy, len, spec);
}

int PWR_DISK_SetScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t len)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(scsiPolicy);
    if (len == 0) {
        return ERR_INVALIDE_PARAM;
    }

    return SetDiskScsiPolicy(scsiPolicy, len);
}


// NET
int PWR_NET_GetInfo(PWR_NET_Info *netInfo, uint32_t bufferSize)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(netInfo);
    if (bufferSize <= sizeof(PWR_NET_Info)) {
        return ERR_INVALIDE_PARAM;
    }

    return GetNetInfo(netInfo, bufferSize);
}

int PWR_NET_GetThrouth(char ethName[], PWR_NET_Through *ethThrough)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(ethName);
    CHECK_NULL_POINTER(ethThrough);

    if (strlen(ethName) == 0 || strlen(ethName) >= MAX_ELEMENT_NAME_LEN) {
        return ERR_INVALIDE_PARAM;
    }

    return GetNetThrough(ethName, ethThrough);
}

int PWR_NET_GetSpeedMod(char ethName[], uint32_t *speedMod)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(ethName);
    CHECK_NULL_POINTER(speedMod);
    if (strlen(ethName) == 0 || strlen(ethName) >= MAX_ELEMENT_NAME_LEN) {
        return ERR_INVALIDE_PARAM;
    }
    return GetNetSpeedMod(ethName, speedMod);
}

int PWR_NET_SetSpeedMod(char ethName[], uint32_t speedMod)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(ethName);
    // todo 限制speedMod取值 100 1000 10000
    return SetNetSpeedMod(ethName, speedMod);
}


// USB
int PWR_USB_GetAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t *len)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(usbAts);
    if (!len || *len == 0) {
        return ERR_INVALIDE_PARAM;
    }

    return GetUsbAutoSuspend(usbAts, len);
}

int PWR_USB_SetAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t len)
{
    CHECK_STATUS();
    CHECK_NULL_POINTER(usbAts);
    if (len == 0) {
        return ERR_INVALIDE_PARAM;
    }

    return SetUsbAutoSuspend(usbAts, len);
}
