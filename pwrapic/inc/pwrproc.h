/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: queyanwen
 * Create: 2023-10-19
 * Description: Provide service for PowerAPI refer to process function.
 * **************************************************************************** */
#ifndef POWERAPI_PROC_H__
#define POWERAPI_PROC_H__
#include <stdint.h>
#include "pwrdata.h"

int QueryProcsByKeywords(const char *keywords, pid_t procs[], uint32_t *num);
int GetProcWattState(int *state);
int SetProcWattState(int state);
int GetProcWattAttrs(PWR_PROC_WattAttrs *wattAttrs);
int SetProcWattAttrs(const PWR_PROC_WattAttrs *wattAttrs);
int GetWattProcs(pid_t wattProcs[], uint32_t *num);
int AddWattProcs(const pid_t wattProcs[], uint32_t num);
int DelWattProcs(const pid_t wattProcs[], uint32_t num);
int GetSmartGridState(int *state);
int SetSmartGridState(int state);
int SetWattFirstDomain(int cpuId);
int GetSmartGridProcs(PWR_PROC_SMART_GRID_LEVEL level, PWR_PROC_SmartGridProcs *sgProcs);
int SetSmartGridLevel(const PWR_PROC_SmartGridProcs *sgProcs);
int GetSmartGridGov(PWR_PROC_SmartGridGov *sgGov);
int SetSmartGridGov(const PWR_PROC_SmartGridGov *sgGov);
int GetServiceState(PWR_PROC_ServiceStatus *sStatus);
int SetServiceState(const PWR_PROC_ServiceState *sState);
#endif
