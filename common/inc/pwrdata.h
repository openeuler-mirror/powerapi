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
 * Author: queyanwen, wuhaotian
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
#define MAX_STRING_LEN 1000
#define MAX_CPU_DMA_LATENCY 2000000000

enum Arch {
    AARCH_64 = 0,
    X86_64 = 1,
};

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
} PWR_CPU_FREQ_GOV; */


typedef struct PWR_CPU_FreqAbility {
    char curDriver[MAX_ELEMENT_NAME_LEN];
    int avGovNum;
    int avGovList[MAX_GOV_NUM][MAX_ELEMENT_NAME_LEN];
    int freqDomainNum;
    int freqDomainStep;
    char freqDomain[0];
} PWR_CPU_FreqAbility;


typedef struct PWR_CPU_CurFreq {
    int policyId;
    double curFreq;
} PWR_CPU_CurFreq;

typedef struct PWR_NET_Eth {
    char ethName[MAX_ELEMENT_NAME_LEN];
    int ethMaxSpeed;
    int ethCurSpeed;
} PWR_NET_Eth;

typedef struct PWR_NET_Info {
    int ethNum;
    PWR_NET_Eth eth[];
} PWR_NET_Info;

typedef struct PWR_NET_Through {
    double rx;
    double tx;
} PWR_NET_Through;

// DISK

typedef struct PWR_DISK_Load {
    char diskId[MAX_ELEMENT_NAME_LEN];
    uint32_t rLoad;
    uint32_t wLoad;
} PWR_DISK_Load;

typedef struct PWR_DISK_PwrLevel {
    char diskId[MAX_ELEMENT_NAME_LEN];
    uint16_t powerLevel;
    uint16_t spindownLevel;
} PWR_DISK_PwrLevel;


typedef struct PWR_DISK_ScsiPolicy {
    char scsiId[MAX_ELEMENT_NAME_LEN];
    int alpm;
} PWR_DISK_ScsiPolicy;

// USB
typedef struct PWR_USB_AutoSuspend {
    char usbId[MAX_ELEMENT_NAME_LEN];
    int control;
    int autoSuspendDelay;
    int wakeup;
} PWR_USB_AutoSuspend;

#endif
