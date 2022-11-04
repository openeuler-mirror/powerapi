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
#ifndef __POWERAPI_CPU_H__
#define __POWERAPI_CPU_H__

#include <stdint.h>
#include "pwrdata.h"
int GetCpuInfo(PWR_CPU_Info *cpuInfo);
int GetCpuUsage(PWR_CPU_Usage *usage, uint32_t bufferSize);
int GetCpuLlcMissPerIns(double *cacheMiss);
int GetCpuFreqAbility(PWR_CPU_FreqAbility *freqAbi, uint32_t bufferSize);
int GetCpuFreqGovernor(char gov[], uint32_t size);
int SetCpuFreqGovernor(char gov[], uint32_t size);
int GetCpuCurFreq(PWR_CPU_CurFreq curFreq[], uint32_t *len, int spec);
int SetCpuCurFreq(PWR_CPU_CurFreq curFreq[], uint32_t len);
int GetCpuDmaLatency(int *latency);
int SetCpuDmaLatency(int latency);
#endif
