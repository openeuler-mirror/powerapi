/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: PowerAPI interface definition. The SI shall include this head file for using the PowerAPI.
 * **************************************************************************** */
#ifndef POWERAPI_H__
#define POWERAPI_H__

#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include "pwrerr.h"
#include "pwrdata.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PWR_API
// Common
PWR_API int PWR_SetLogCallback(void(LogCallback)(int level, const char *fmt, va_list vl));
PWR_API int PWR_SetServerInfo(const char* socketPath);
PWR_API int PWR_SetClientSockPath(const char* socketPath);
PWR_API int PWR_Register(void);
PWR_API int PWR_UnRegister(void);
PWR_API int PWR_RequestControlAuth(void);
PWR_API int PWR_ReleaseControlAuth(void);
// CPU
PWR_API int PWR_CPU_GetInfo(PWR_CPU_Info *cpuInfo);
PWR_API int PWR_CPU_GetFreqAbility(PWR_CPU_FreqAbility *freqAbi, uint32_t bufferSize);
PWR_API int PWR_CPU_GetFreqGovernor(char gov[], uint32_t size); // len: PWR_MAX_ELEMENT_NAME_LEN
PWR_API int PWR_CPU_SetFreqGovernor(const char gov[]);
PWR_API int PWR_CPU_GetFreqGovAttrs(PWR_CPU_FreqGovAttrs *govAttrs);
PWR_API int PWR_CPU_GetFreqGovAttr(PWR_CPU_FreqGovAttr *govAttr);
PWR_API int PWR_CPU_SetFreqGovAttr(const PWR_CPU_FreqGovAttr *govAttr);
PWR_API int PWR_CPU_GetFreqRange(PWR_CPU_FreqRange *freqRange);
PWR_API int PWR_CPU_SetFreqRange(const PWR_CPU_FreqRange *freqRange);
PWR_API int PWR_CPU_GetFreq(PWR_CPU_CurFreq curFreq[], uint32_t *num, int spec);
PWR_API int PWR_CPU_SetFreq(const PWR_CPU_CurFreq curFreq[], uint32_t num);
PWR_API int PWR_CPU_GetIdleInfo(PWR_CPU_IdleInfo *idleInfo);
PWR_API int PWR_CPU_GetIdleGovernor(char idleGov[], uint32_t size); // unit: us
PWR_API int PWR_CPU_SetIdleGovernor(const char idleGov[]);
PWR_API int PWR_CPU_DmaGetLatency(int *latency); // unit: us
PWR_API int PWR_CPU_DmaSetLatency(int latency);

#ifndef RELEASE_MODE
// Common
PWR_API int PWR_SetMetaDataCallback(void(MetaDataCallback)(const PWR_COM_CallbackData *callbackData));
PWR_API int PWR_CreateDcTask(const PWR_COM_BasicDcTaskInfo *basicDcTaskInfo);
PWR_API int PWR_DeleteDcTask(PWR_COM_COL_DATATYPE dataType);
PWR_API int PWR_SetEventCallback(void(EventCallback)(const PWR_COM_EventInfo* eventInfo));

// SYS
PWR_API int PWR_SYS_SetPowerState(const int powerState);
PWR_API int PWR_SYS_GetCappedPower(int *cappedPower);
PWR_API int PWR_SYS_SetCappedPower(const int cappedPower);
PWR_API int PWR_SYS_GetRtPowerInfo(PWR_SYS_PowerInfo *powerInfo);
PWR_API int PWR_SYS_GetStatisticPowerInfo(PWR_SYS_StatisticPowerInfo *stcPowerInfo);

// CPU
PWR_API int PWR_CPU_GetUsage(PWR_CPU_Usage *usage, uint32_t bufferSize);
PWR_API int PWR_CPU_GetPerfData(PWR_CPU_PerfData *perfData);

// Disk
PWR_API int PWR_DISK_GetList(char diskList[][PWR_MAX_ELEMENT_NAME_LEN], uint32_t *len);
PWR_API int PWR_DISK_GetLoad(PWR_DISK_Load load[], uint32_t *len, int spec);
PWR_API int PWR_DISK_GetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t *len, int spec);
PWR_API int PWR_DISK_SetPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t len);
PWR_API int PWR_DISK_GetScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t *len, int spec);
PWR_API int PWR_DISK_SetScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t len);

// NET
PWR_API int PWR_NET_GetInfo(PWR_NET_Info *netInfo, uint32_t bufferSize);
PWR_API int PWR_NET_GetThrouth(char ethName[], PWR_NET_Through *ethThrough);
PWR_API int PWR_NET_GetSpeedMod(char ethName[], uint32_t *speedMod);
PWR_API int PWR_NET_SetSpeedMod(char ethName[], uint32_t speedMod);

// USB
PWR_API int PWR_USB_GetAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t *len);
PWR_API int PWR_USB_SetAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t len);

// PROC
PWR_API int PWR_PROC_QueryProcs(const char *keywords, pid_t procs[], uint32_t *num);
PWR_API int PWR_PROC_GetWattState(int *state);
PWR_API int PWR_PROC_SetWattState(int state);
PWR_API int PWR_PROC_SetWattFirstDomain(int cpuId);
PWR_API int PWR_PROC_GetWattAttrs(PWR_PROC_WattAttrs *wattAttrs);
PWR_API int PWR_PROC_SetWattAttrs(const PWR_PROC_WattAttrs *wattAttrs);
PWR_API int PWR_PROC_GetWattProcs(pid_t wattProcs[], uint32_t *num);
PWR_API int PWR_PROC_AddWattProcs(const pid_t wattProcs[], uint32_t num);
PWR_API int PWR_PROC_DelWattProcs(const pid_t wattProcs[], uint32_t num);
PWR_API int PWR_PROC_GetSmartGridState(int *state);
PWR_API int PWR_PROC_SetSmartGridState(int state);
PWR_API int PWR_PROC_GetSmartGridProcs(PWR_PROC_SMART_GRID_LEVEL level, PWR_PROC_SmartGridProcs *sgProcs);
PWR_API int PWR_PROC_SetSmartGridLevel(const PWR_PROC_SmartGridProcs *sgProcs);
PWR_API int PWR_PROC_GetSmartGridGov(PWR_PROC_SmartGridGov *sgGov);
PWR_API int PWR_PROC_SetSmartGridGov(const PWR_PROC_SmartGridGov *sgGov);
PWR_API int PWR_PROC_GetServiceState(PWR_PROC_ServiceStatus *sStatus);
PWR_API int PWR_PROC_SetServiceState(PWR_PROC_ServiceState *sState);

// HBM
PWR_API int PWR_HBM_GetSysState(PWR_HBM_SYS_STATE *hbmState);
PWR_API int PWR_HBM_SetAllPwrState(int state);

#endif // #ifndef RELEASE_MODE

#ifdef __cplusplus
}
#endif

#endif // #ifndef POWERAPI_H__