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
 * Description: Provide service for PowerAPI refer to CPU.
 * **************************************************************************** */
#ifndef POWERAPI_CPU_H__
#define POWERAPI_CPU_H__

#include <stdint.h>
#include "pwrdata.h"
int GetCpuInfo(PWR_CPU_Info *cpuInfo);
int GetCpuUsage(PWR_CPU_Usage *usage, uint32_t bufferSize);
int GetCpuPerfData(PWR_CPU_PerfData *perfData);
int GetCpuFreqAbility(PWR_CPU_FreqAbility *freqAbi, uint32_t bufferSize);
int GetCpuFreqRange(PWR_CPU_FreqRange *freqRange);
int SetCpuFreqRange(const PWR_CPU_FreqRange *freqRange);
int GetCpuFreqGovernor(char gov[], uint32_t size);
int SetCpuFreqGovernor(const char gov[], uint32_t size);
int GetCpuFreqGovAttrs(PWR_CPU_FreqGovAttrs *govAttrs);
int GetCpuFreqGovAttr(PWR_CPU_FreqGovAttr *govAttr);
int SetCpuFreqGovAttr(const PWR_CPU_FreqGovAttr *govAttr);
int GetCpuCurFreq(PWR_CPU_CurFreq curFreq[], uint32_t *num, int spec);
int SetCpuCurFreq(const PWR_CPU_CurFreq curFreq[], uint32_t num);
int GetCpuDmaLatency(int *latency);
int SetCpuDmaLatency(int latency);
#endif
