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
#include "pwrproc.h"
#include "pwrhbm.h"

#define CHECK_STATUS(s)                           \
    {                                             \
        if ((s) > GetPwrApiStatus()) {                     \
            if ((s) == STATUS_REGISTERTED) {      \
                PwrLog(ERROR, "Not registed.");   \
                return PWR_ERR_NOT_REGISTED;          \
            } else {                              \
                PwrLog(ERROR, "Not authorized."); \
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

static const char *GetLogLevelName(int level)
{
    static char debug[] = "DEBUG";
    static char info[] = "INFO";
    static char warning[] = "WARNING";
    static char error[] = "ERROR";
    switch (level) {
        case DEBUG:
            return debug;
        case INFO:
            return info;
        case WARNING:
            return warning;
        case ERROR:
            return error;
        default:
            return info;
    }
}

#define LOG_TAB 5
static void DefaultLogCallback(int level, const char *fmt, va_list vl)
{
    char message[PWR_MAX_LOG_LEN] = {0};
    if (vsnprintf(message, sizeof(message) - 1, fmt, vl) < 0) {
        return;
    }
    printf("[%-*s]    %s\n", LOG_TAB, GetLogLevelName(level), message);
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
    if (GetPwrApiStatus() != STATUS_UNREGISTERED) {
        return PWR_SUCCESS;
    }
    if (InitSockClient() != PWR_SUCCESS) {
        return PWR_ERR_COMMON;
    }
    if (GetPwrApiStatus() == STATUS_UNREGISTERED) {
        (void)SetPwrApiStatus(STATUS_REGISTERTED);
    }
    return PWR_SUCCESS;
}

int PWR_UnRegister(void)
{
    int ret = FiniSockClient();
    (void)SetPwrApiStatus(STATUS_UNREGISTERED);
    return ret;
}


int PWR_RequestControlAuth(void)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    int ret = RequestControlAuth();
    if (ret == PWR_SUCCESS) {
        (void)SetPwrApiStatus(STATUS_AUTHED);
    }
    return ret;
}

int PWR_ReleaseControlAuth(void)
{
    CHECK_STATUS(STATUS_AUTHED);
    int ret = ReleaseControlAuth();
    if (ret == PWR_SUCCESS) {
        (void)SetPwrApiStatus(STATUS_REGISTERTED);
    }
    return ret;
}

int PWR_CPU_GetInfo(PWR_CPU_Info *cpuInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(cpuInfo);

    return GetCpuInfo(cpuInfo);
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
    if (freqRange->minFreq < 0 || freqRange->minFreq >= freqRange->maxFreq) {
        return PWR_ERR_INVALIDE_PARAM;
    }

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

int PWR_CPU_GetFreqGovAttrs(PWR_CPU_FreqGovAttrs *govAttrs)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(govAttrs);
    return GetCpuFreqGovAttrs(govAttrs);
}

int PWR_CPU_GetFreqGovAttr(PWR_CPU_FreqGovAttr *govAttr)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(govAttr);
    return GetCpuFreqGovAttr(govAttr);
}

int PWR_CPU_SetFreqGovAttr(const PWR_CPU_FreqGovAttr *govAttr)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(govAttr);
    return SetCpuFreqGovAttr(govAttr);
}

int PWR_CPU_GetFreq(PWR_CPU_CurFreq curFreq[], uint32_t *num, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(curFreq);
    if (!num || *num == 0 || (spec != PWR_TRUE && spec != PWR_FALSE)) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return GetCpuCurFreq(curFreq, num, spec);
}

int PWR_CPU_SetFreq(const PWR_CPU_CurFreq curFreq[], uint32_t num)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(curFreq);
    if (num == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetCpuCurFreq(curFreq, num);
}

int PWR_CPU_GetIdleInfo(PWR_CPU_IdleInfo *idleInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(idleInfo);
    if (idleInfo->cstateNum == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return GetCpuIdleInfo(idleInfo);
}

int PWR_CPU_GetIdleGovernor(char idleGov[], uint32_t size)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(idleGov);
    if (size < PWR_MAX_ELEMENT_NAME_LEN) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return GetCpuIdleGov(idleGov, size);
}

int PWR_CPU_SetIdleGovernor(const char idleGov[])
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(idleGov);
    if (strlen(idleGov) <= 0 || strlen(idleGov) >= PWR_MAX_ELEMENT_NAME_LEN) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetCpuIdleGov(idleGov);
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

// HBM
int PWR_HBM_GetSysState(PWR_HBM_SysState *hbmState)
{
    CHECK_STATUS(STATUS_REGISTERTED);

    return GetHbmSysState(hbmState);
}

int PWR_HBM_SetAllPwrState(int state)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (state < 0 || state > 1) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetAllHbmPowerState(state);
}

#ifndef RELEASE_MODE
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


int PWR_SYS_SetPowerState(const int powerState)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (powerState != PWR_MEM && powerState != PWR_DISK) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetSysPowerState(powerState);
}

int PWR_SYS_GetCappedPower(int *cappedPower)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(cappedPower);

    return GetCappedPower(cappedPower);
}

int PWR_SYS_SetCappedPower(const int cappedPower)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (cappedPower <= 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetCappedPower(cappedPower);
}

int PWR_SYS_GetRtPowerInfo(PWR_SYS_PowerInfo *powerInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(powerInfo);

    return GetSysRtPowerInfo(powerInfo);
}

int PWR_SYS_GetStatisticPowerInfo(PWR_SYS_StatisticPowerInfo *stcPowerInfo)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(stcPowerInfo);

    return GetStatisticPowerInfo(stcPowerInfo);
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

// Disk
int PWR_DISK_GetList(char diskList[][PWR_MAX_ELEMENT_NAME_LEN], uint32_t *len)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(diskList);
    CHECK_NULL_POINTER(len);
    if (!len || *len == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetDiskList(diskList, len);
}

int PWR_DISK_GetLoad(PWR_DISK_Load load[], uint32_t *len, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(load);
    CHECK_NULL_POINTER(len);
    if (!len || *len == 0 || (spec != PWR_TRUE && spec != PWR_FALSE)) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return GetDiskLoad(load, len, spec);
}

int PWR_DISK_GetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t *len, int spec)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(pwrLevel);
    CHECK_NULL_POINTER(len);
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
    CHECK_NULL_POINTER(len);
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
    CHECK_NULL_POINTER(len);
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

// PROC
int PWR_PROC_QueryProcs(const char *keywords, pid_t procs[], uint32_t *num)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(procs);
    CHECK_NULL_POINTER(num);
    if (*num == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    const char *kw = "";
    if (keywords) {
        if (strlen(keywords) >= PWR_MAX_STRING_LEN) {
            return PWR_ERR_INVALIDE_PARAM;
        }
        kw = keywords;
    }
    return QueryProcsByKeywords(kw, procs, num);
}

int PWR_PROC_GetWattState(int *state)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(state);
    return GetProcWattState(state);
}

int PWR_PROC_SetWattFirstDomain(int cpuId)
{
    CHECK_STATUS(STATUS_AUTHED);

    if (cpuId < 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    return SetWattFirstDomain(cpuId);
}

int PWR_PROC_SetWattState(int state)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (state != PWR_ENABLE && state != PWR_DISABLE) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetProcWattState(state);
}

int PWR_PROC_GetWattAttrs(PWR_PROC_WattAttrs *wattAttrs)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(wattAttrs);
    return GetProcWattAttrs(wattAttrs);
}

int PWR_PROC_SetWattAttrs(const PWR_PROC_WattAttrs *wattAttrs)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(wattAttrs);
    if (wattAttrs->scaleThreshold < 0 || wattAttrs->scaleThreshold > PWR_ONE_HUNDRED ||
        wattAttrs->scaleInterval < 0 || wattAttrs->scaleInterval > PWR_MAX_WATT_SCALE_INTERVAL ||
        wattAttrs->domainMask < 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetProcWattAttrs(wattAttrs);
}

int PWR_PROC_GetWattProcs(pid_t wattProcs[], uint32_t *num)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(wattProcs);
    CHECK_NULL_POINTER(num);
    if (*num == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return GetWattProcs(wattProcs, num);
}

int PWR_PROC_AddWattProcs(const pid_t wattProcs[], uint32_t num)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(wattProcs);
    if (num == 0 || num > PWR_MAX_PROC_NUM) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return AddWattProcs(wattProcs, num);
}

int PWR_PROC_DelWattProcs(const pid_t wattProcs[], uint32_t num)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(wattProcs);
    if (num == 0 || num > PWR_MAX_PROC_NUM) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return DelWattProcs(wattProcs, num);
}

int PWR_PROC_GetSmartGridState(int *state)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(state);
    return GetSmartGridState(state);
}

int PWR_PROC_SetSmartGridState(int state)
{
    CHECK_STATUS(STATUS_AUTHED);
    if (state != PWR_ENABLE && state != PWR_DISABLE) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetSmartGridState(state);
}

int PWR_PROC_GetSmartGridProcs(PWR_PROC_SMART_GRID_LEVEL level, PWR_PROC_SmartGridProcs *sgProcs)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(sgProcs);
    if (sgProcs->procNum == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return GetSmartGridProcs(level, sgProcs);
}

int PWR_PROC_SetSmartGridLevel(const PWR_PROC_SmartGridProcs *sgProcs)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(sgProcs);
    if (sgProcs->procNum == 0  || sgProcs->procNum > PWR_MAX_PROC_NUM) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetSmartGridLevel(sgProcs);
}

int PWR_PROC_GetSmartGridGov(PWR_PROC_SmartGridGov *sgGov)
{
    CHECK_STATUS(STATUS_REGISTERTED);
    CHECK_NULL_POINTER(sgGov);
    return GetSmartGridGov(sgGov);
}

int PWR_PROC_SetSmartGridGov(const PWR_PROC_SmartGridGov *sgGov)
{
    CHECK_STATUS(STATUS_AUTHED);
    CHECK_NULL_POINTER(sgGov);
    if (sgGov->sgAgentState != PWR_ENABLE && sgGov->sgAgentState != PWR_DISABLE) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    return SetSmartGridGov(sgGov);
}

#endif  // #ifndef RELEASE_MODE