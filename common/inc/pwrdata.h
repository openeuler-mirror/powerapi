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
 * Description: The structures definition of powerAPI.
 * **************************************************************************** */
#ifndef __POWERAPI_DATA_H__
#define __POWERAPI_DATA_H__

#define MAX_ELEMENT_NAME_LEN 32
#define MAX_NAME_LEN 128
#define MAX_CPU_LIST_LEN 248
#define MAX_NUMA_NODE_NUM 16
#define MAX_GOV_NUM 16

#define MAX_CPU_DMA_LATENCY 2000000000

typedef struct PWR_CPU_NumaInfo {
    int nodeNo;
    char cpuList[MAX_CPU_LIST_LEN];
} PWR_CPU_NumaInfo;

typedef struct PWR_CPU_Info {
    char arch[MAX_ELEMENT_NAME_LEN];
    char modelName[MAX_NAME_LEN];
    int byteOrder;
    int coreNum;
    char onlineList[MAX_CPU_LIST_LEN];
    int threadsPerCore;
    int coresperSocket;
    double maxFreq;
    double minFreq;
    int numaNum;
    PWR_CPU_NumaInfo numa[MAX_NUMA_NODE_NUM];
} PWR_CPU_Info;

typedef struct PWR_CPU_CoreUsage {
    int coreNo;
    double usage;
} PWR_CPU_CoreUsage;

typedef struct PWR_CPU_Usage {
    double avgUsage;
    int coreNum;
    PWR_CPU_CoreUsage coreUsage[0];
} PWR_CPU_Usage;

/*
typedef enum PWR_CPU_FREQ_DRIVER {
    PWR_CPU_FREQ_DRV_CPPC = 1,      // cppc_cpufreq
    PWR_CPU_FREQ_DRV_INTEL,         // intel_cpufreq
    PWR_CPU_FREQ_DRV_INTEL_PSTATE,  // intel_pstate
} PWR_CPU_FREQ_DRIVER;

typedef enum PWR_CPU_FREQ_GOV {
    PWR_CPU_FREQ_GOV_CONSERVATIVE = 1,      // conservative governor
    PWR_CPU_FREQ_GOV_ONDEMAND,              // ondemand governoor
    PWR_CPU_FREQ_GOV_USERSPACE,             // userspace governor
    PWR_CPU_FREQ_GOV_POWERSAVE,             // powersave governor
    PWR_CPU_FREQ_GOV_PERFORMANCE = 5,       // performance governor
    PWR_CPU_FREQ_GOV_SCHEDUTIL,             // schedutil governor
    PWR_CPU_FREQ_GOV_SEEP,                  // seep governor
} PWR_CPU_FREQ_GOV;*/

typedef struct PWR_CPU_FreqAbility {
    char curDriver[MAX_ELEMENT_NAME_LEN];
    int avGovNum; 
    int avGovList[MAX_GOV_NUM][MAX_ELEMENT_NAME_LEN];
} PWR_CPU_FreqAbility;

#endif
