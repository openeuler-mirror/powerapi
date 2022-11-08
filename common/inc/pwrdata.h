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
#include <stdint.h>
#define MAX_ELEMENT_NAME_LEN 32
#define MAX_ARRRIBUTES 11
#define MAX_NAME_LEN 128
#define MAX_CPU_LIST_LEN 248
#define MAX_NUMA_NODE_NUM 16
#define MAX_GOV_NUM 16
#define MAX_STRING_LEN 1000
#define MAX_TIME_LEN 24
#define MAX_DC_INTERVAL 100000000
#define MIN_DC_INTERVAL 500
#define CPU_USAGE_COLUMN 8
#define CPUS_WIDTH 6
#define LATENCY 100000
#define CPU_IDLE_COLUMN 3
#define DECIMAL 10
#define CONVERSION 1000

#define MAX_CPU_DMA_LATENCY 2000000000
#define MAX_DISK_LIST_LEN 128

enum Arch {
    AARCH_64 = 0,
    X86_64 = 1,
};

enum CpuAttType {
    ARCH = 0,
    MODEL_NAME,
    BYTE_OR,
    NUMA_NUMBER,
    NUMA_NODE,
    CPU_NUMBER,
    ONLINE_CPU,
    THREADS_PER_CORE,
    CORES_PER_SOCKET,
    MAX_MHZ,
    MIN_MHZ,
};

typedef enum PWR_COM_COL_DATATYPE {
    PWR_COM_DATATYPE_LLC_MISS = 1,
    PWR_COM_DATATYPE_CPU_USAGE,
    PWR_COM_DATATYPE_CPU_IPC,
    PWR_COM_DATATYPE_INVALIDE,
} PWR_COM_COL_DATATYPE;

typedef struct PWR_COM_CallbackData {
    char ctime[MAX_TIME_LEN];
    int dataType;
    int dataLen;
    void *data;
} PWR_COM_CallbackData;

typedef struct PWR_COM_BasicDcTaskInfo {
    PWR_COM_COL_DATATYPE dataType;
    int interval;
} PWR_COM_BasicDcTaskInfo;

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

typedef struct PWR_DISK_Info {
    char diskId[MAX_ELEMENT_NAME_LEN];
} PWR_DISK_Info;

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
