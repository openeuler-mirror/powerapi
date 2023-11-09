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
 * Description: provide cpu service
 * **************************************************************************** */
#ifndef PAPIS_CPU_SERVICE_H__
#define PAPIS_CPU_SERVICE_H__
#include "pwrmsg.h"
#include "pwrdata.h"

int GetArch(void);
void GetCpuinfo(PwrMsg *req);
void GetCpuUsage(PwrMsg *req);
void GetCpuPerfData(PwrMsg *req);
void GetCpuFreq(PwrMsg *req);
void SetCpuFreq(PwrMsg *req);
int PerfDataRead(PWR_CPU_PerfData *perfData);
int CPUUsageRead(PWR_CPU_Usage *rstData, int coreNum);
int CurrentGovernorRead(char *gov);
int SetGovernorForAllPcy(const char *gov);
void GetCpuFreqGovernor(PwrMsg *req);
void SetCpuFreqGovernor(PwrMsg *req);
void GetCpuFreqGovAttrs(PwrMsg *req);
void GetCpuFreqGovAttr(PwrMsg *req);
void SetCpuFreqGovAttr(PwrMsg *req);
void GetCpuFreqAbility(PwrMsg *req);
void GetCpuFreqRange(PwrMsg *req);
void SetCpuFreqRange(PwrMsg *req);
int GetCpuCoreNumber(void);
void GetCpuIdleInfo(PwrMsg *req);
void GetCpuIdleGov(PwrMsg *req);
void SetCpuIdleGov(PwrMsg *req);
void GetCpuDmaLatency(PwrMsg *req);
void SetCpuDmaLatency(PwrMsg *req);
#endif
