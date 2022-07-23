/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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
#ifndef __POWERAPI_H__
#define __POWERAPI_H__

#include <stdarg.h>
#include <stdint.h>
#include "pwrerr.h"
#include "pwrdata.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PWR_API


// common
PWR_API int PWR_SetLogCallback(void(LogCallback)(int level, const char *fmt, va_list vl));
PWR_API int PWR_Register();
PWR_API int PWR_UnRegister();

// CPU
PWR_API int PWR_CPU_GetInfo(PWR_CPU_Info *cpuInfo);
PWR_API int PWR_CPU_GetUsage(PWR_CPU_Usage *usage, uint32_t bufferSize);
PWR_API int PWR_CPU_GetFreqAbility(PWR_CPU_FreqAbility *freqAbi);
PWR_API int PWR_CPU_GetFreqGovernor(char gov[], uint32_t size);    // len: MAX_ELEMENT_LEN
PWR_API int PWR_CPU_SetFreqGovernor(char gov[]);

PWR_API int PWR_CPU_DmaGetLatency(int *latency);    // unit: us
PWR_API int PWR_CPU_DmaSetLatency(int latency);

#ifdef __cplusplus
}
#endif

#endif
