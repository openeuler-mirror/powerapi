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
 * Description: PowerAPI interface implementation.
 * **************************************************************************** */

#include "powerapi.h"
#include <stdio.h>
#include <string.h>
#include "pwrlog.h"
#include "pwrdata.h"
#include "sockclient.h"
#include "pwrtask.h"
#include "pwrsys.h"
#include "pwrcom.h"
#include "pwrcpu.h"
#include "pwrdisk.h"
#include "pwrnet.h"
#include "pwrusb.h"

typedef enum PwrApiStatus {
    STATUS_UNREGISTERED = 0,
    STATUS_REGISTERTED = 1,
    STATUS_AUTHED = 2,
} PwrApiStatus;

static PwrApiStatus g_status = STATUS_UNREGISTERED;

#define CHECK_STATUS(s)                           \
    {                                             \
        if ((s) > g_status) {                     \
            if ((s) == STATUS_REGISTERTED) {      \
                PwrLog(ERROR, "Not Registed.");   \
                return PWR_ERR_NOT_REGISTED;          \
            } else {                              \
                PwrLog(ERROR, "Not Authorized."); \
                return PWR_ERR_NOT_AUTHED;            \
            }                                     \
        }                                         \
    }

#define CHECK_NULL_POINTER(p)        \
    {                                \
        if (!(p)) {                  \
            return PWR_ERR_NULL_POINTER; \
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
        return PWR_SUCCESS;
    }
    return PWR_ERR_NULL_POINTER;
}

int PWR_SetServerInfo(const char* socketPath)
{
    if (socketPath) {
        return SetServerInfo(socketPath);
    }
    return PWR_ERR_NULL_POINTER;
}

int PWR_Register(void)
{
    // todo: 增加必要的其他初始化动作
    if (InitSockClient() != PWR_SUCCESS) {
        return PWR_ERR_COMMON;
    }
    if (g_status == STATUS_UNREGISTERED) {
        g_status = STATUS_REGISTERTED;
    }
    return PWR_SUCCESS;
}

int PWR_UnRegister(void)
{
    int ret = FiniSockClient();
    // todo: 增加必要的其他去初始化动作
    g_status = STATUS_UNREGISTERED;
    return ret;
}


int PWR_SetMetaDataCallback(void(MetaDataCallback)(const PWR_COM_CallbackData *))
{
    if (MetaDataCallback) {
        return SetMetaDataCallback(MetaDataCallback);
    }
    return PWR_ERR_NULL_POINTER;
}

int PWR_CreateDcTask(const PWR_COM_BasicDcTaskInfo *basicDcTaskInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(basicDcTaskInfo);

    if (basicDcTaskInfo->interval < PWR_MIN_DC_INTERVAL || basicDcTaskInfo->interval > PWR_MAX_DC_INTERVAL) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    if (!HasSetDataCallback()) {
        return PWR_ERR_CALLBACK_FUNCTION_SHOULD_BE_SET_FIRST;
    }

    return CreateDcTask(basicDcTaskInfo);
}

int PWR_DeleteDcTask(PWR_COM_COL_DATATYPE dataType)
{
    CHECK_STATUS(STATUS_REGISTERTED);

    return DeleteDcTask(dataType);
}

int PWR_SetEventCallback(void(EventCallback)(const PWR_COM_EventInfo *))
{
    if (EventCallback) {
        return SetEventCallback(EventCallback);
    }
    return PWR_ERR_NULL_POINTER;
}

int PWR_RequestControlAuth(void)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    int ret = RequestControlAuth();
    if (ret == PWR_SUCCESS) {
        g_status = STATUS_AUTHED;
    }
    return ret;
}

int PWR_ReleaseControlAuth(void)
{
    CHECK_STATUS(STATUS_AUTHED);
    int ret = ReleaseControlAuth();
    if (ret == PWR_SUCCESS) {
        g_status = STATUS_REGISTERTED;
    }
    return ret;
}

int PWR_SYS_SetPowerState(int powerState)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (powerState != PWR_MEM && powerState != PWR_DISK) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetSysPowerState(powerState);
}

int PWR_SYS_GetRtPowerInfo(PWR_SYS_PowerInfo *powerInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(powerInfo);
    return GetSysRtPowerInfo(powerInfo);
}

int PWR_CPU_GetInfo(PWR_CPU_Info *cpuInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(cpuInfo);

    return GetCpuInfo(cpuInfo);
}

int PWR_CPU_GetUsage(PWR_CPU_Usage *usage, uint32_t bufferSize)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(usage);
    if (bufferSize < sizeof(PWR_CPU_Usage)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetCpuUsage(usage, bufferSize);
}

PWR_API int PWR_CPU_GetPerfData(PWR_CPU_PerfData *perfData)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(perfData);

    return GetCpuPerfData(perfData);
}

int PWR_CPU_GetFreqAbility(PWR_CPU_FreqAbility *freqAbi, uint32_t bufferSize)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(freqAbi);
    if (bufferSize < sizeof(PWR_CPU_FreqAbility)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetCpuFreqAbility(freqAbi, bufferSize);
}

int PWR_CPU_GetFreqRange(PWR_CPU_FreqRange *freqRange)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(freqRange);

    return GetCpuFreqRange(freqRange);
}

int PWR_CPU_SetFreqRange(const PWR_CPU_FreqRange *freqRange)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(freqRange);

    return SetCpuFreqRange(freqRange);
}

int PWR_CPU_GetFreqGovernor(char gov[], uint32_t size)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(gov);
    if (size < PWR_MAX_ELEMENT_NAME_LEN) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetCpuFreqGovernor(gov, size);
}

int PWR_CPU_SetFreqGovernor(const char gov[])
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(gov);
    if (strlen(gov) == 0 || strlen(gov) >= PWR_MAX_ELEMENT_NAME_LEN) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetCpuFreqGovernor(gov, strlen(gov) + 1);
}

int PWR_CPU_GetFreq(PWR_CPU_CurFreq curFreq[], uint32_t *len, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(curFreq);
    if (!len || *len == 0 || (spec != PWR_TRUE && spec != PWR_FALSE)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetCpuCurFreq(curFreq, len, spec);
}

int PWR_CPU_SetFreq(const PWR_CPU_CurFreq curFreq[], uint32_t len)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(curFreq);
    if (len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetCpuCurFreq(curFreq, len);
}

int PWR_CPU_DmaGetLatency(int *latency)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(latency);

    return GetCpuDmaLatency(latency);
}

int PWR_CPU_DmaSetLatency(int latency)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (latency < 0 || latency > PWR_MAX_CPU_DMA_LATENCY) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetCpuDmaLatency(latency);
}


// Disk
int PWR_DISK_GetList(char diskList[][PWR_MAX_ELEMENT_NAME_LEN], uint32_t *len)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(diskList);
    if (!len || *len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetDiskList(diskList, len);
}

int PWR_DISK_GetLoad(PWR_DISK_Load load[], uint32_t *len, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(load);
    if (!len || *len == 0 || (spec != PWR_TRUE && spec != PWR_FALSE)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetDiskLoad(load, len, spec);
}

int PWR_DISK_GetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t *len, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(pwrLevel);
    if (!len || *len == 0 || (spec != PWR_TRUE && spec != PWR_FALSE)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetDiskPwrLevel(pwrLevel, len, spec);
}

int PWR_DISK_SetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t len)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(pwrLevel);
    if (len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetDiskPwrLevel(pwrLevel, len);
}

int PWR_DISK_GetScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t *len, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(scsiPolicy);
    if (!len || *len == 0 || (spec != PWR_TRUE && spec != PWR_FALSE)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetDiskScsiPolicy(scsiPolicy, len, spec);
}

int PWR_DISK_SetScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t len)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(scsiPolicy);
    if (len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetDiskScsiPolicy(scsiPolicy, len);
}


// NET
int PWR_NET_GetInfo(PWR_NET_Info *netInfo, uint32_t bufferSize)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(netInfo);
    if (bufferSize <= sizeof(PWR_NET_Info)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetNetInfo(netInfo, bufferSize);
}

int PWR_NET_GetThrouth(char ethName[], PWR_NET_Through *ethThrough)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(ethName);
    CHECK_NULL_POINTER(ethThrough);

    if (strlen(ethName) == 0 || strlen(ethName) >= PWR_MAX_ELEMENT_NAME_LEN) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetNetThrough(ethName, ethThrough);
}

int PWR_NET_GetSpeedMod(char ethName[], uint32_t *speedMod)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(ethName);
    CHECK_NULL_POINTER(speedMod);
    if (strlen(ethName) == 0 || strlen(ethName) >= PWR_MAX_ELEMENT_NAME_LEN) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return GetNetSpeedMod(ethName, speedMod);
}

int PWR_NET_SetSpeedMod(char ethName[], uint32_t speedMod)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(ethName);
    // todo 限制speedMod取值 100 1000 10000
    return SetNetSpeedMod(ethName, speedMod);
}

// USB
int PWR_USB_GetAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t *len)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(usbAts);
    if (!len || *len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetUsbAutoSuspend(usbAts, len);
}

int PWR_USB_SetAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t len)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(usbAts);
    if (len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetUsbAutoSuspend(usbAts, len);
}
