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
#ifndef POWERAPI_DATA_H__
#define POWERAPI_DATA_H__

#include <stdint.h>
#include <sys/types.h>
#define PWR_MAX_ELEMENT_NAME_LEN 32
#define PWR_MAX_LOG_LEN 4000
#define PWR_MAX_ARRRIBUTES 11
#define PWR_MAX_NAME_LEN 128
#define PWR_MAX_VALUE_LEN 32
#define PWR_MAX_CPU_LIST_LEN 248
#define PWR_MAX_CPUFREQ_POLICY_NUM 4096
#define PWR_MAX_NUMA_NODE_NUM 128
#define PWR_MAX_GOV_NUM 16
#define PWR_MAX_STRING_LEN 1000
#define PWR_MAX_TIME_LEN 25
#define PWR_MAX_DC_INTERVAL 100000000
#define PWR_MIN_DC_INTERVAL 1000
#define PWR_CPU_USAGE_COLUMN 8
#define PWR_CPUS_WIDTH 6
#define PWR_LATENCY 500000
#define PWR_CPU_IDLE_COLUMN 4
#define PWR_DECIMAL 10
#define PWR_CONVERSION 1000
#define PWR_MAX_CPU_ID_WIDTH 5
#define PWR_MAX_GOV_ATTR_NUM 20
#define PWR_MAX_IDLE_GOV_NUM 8
#define PWR_MAX_CPU_CSTATE_NUM 10

#define PWR_MAX_CPU_DMA_LATENCY 2000000000
#define PWR_MAX_DISK_LIST_LEN 128
#define PWR_INIT_RESERVED_LEN 32
#define PWR_ONE_HUNDRED 100
#define PWR_ONE_THOUSAND 1000
#define PWR_MAX_WATT_SCALE_INTERVAL 3600000
#define PWR_MAX_PROC_NUM 5000

#define PWR_TRUE 1
#define PWR_FALSE 0
#define PWR_ENABLE 1
#define PWR_DISABLE 0
#define PWR_STATE_LEN 4
#define PWR_SERVICE_START 1
#define PWR_SERVICE_STOP 0

enum PWR_Arch {
    PWR_AARCH_64 = 0,
    PWR_X86_64 = 1,
};

enum PWR_SYS_POWER_STATE {
    PWR_MEM = 1,
    PWR_DISK = 2,
};

enum PWR_CpuAttType {
    PWR_ARCH = 0,
    PWR_MODEL_NAME,
    PWR_BYTE_OR,
    PWR_NUMA_NUMBER,
    PWR_NUMA_NODE,
    PWR_CPU_NUMBER,
    PWR_ONLINE_CPU,
    PWR_THREADS_PER_CORE,
    PWR_CORES_PER_SOCKET,
    PWR_MAX_MHZ,
    PWR_MIN_MHZ,
};
typedef enum PWR_PROC_SMART_GRID_LEVEL {
    PWR_PROC_SG_LEVEL_0 = 0,
    PWR_PROC_SG_LEVEL_1 = 1,
} PWR_PROC_SMART_GRID_LEVEL;

typedef enum PWR_PROC_SERVICE_NAME {
    PWR_PROC_SERVICE_INVALIDE = 0,
    PWR_PROC_SERVICE_MPCTOOL,
    PWR_PROC_SERVICE_EAGLE,
} PWR_PROC_SERVICE_NAME;

typedef enum PWR_PROC_SERVICE_STATUS {
    PWR_PROC_SRV_ST_INACTIVE = 0,
    PWR_PROC_SRV_ST_ACTIVATING,
    PWR_PROC_SRV_ST_RUNNING,
    PWR_PROC_SRV_ST_EXITED,
    PWR_PROC_SRV_ST_WAITING,
    PWR_PROC_SRV_ST_FAILED = 5,
    PWR_PROC_SRV_ST_UNKNOWN = 99,
} PWR_PROC_SERVICE_STATUS;

typedef enum PWR_COM_COL_DATATYPE {
    PWR_COM_DATATYPE_CPU_PERF = 1,
    PWR_COM_DATATYPE_CPU_USAGE,
    PWR_COM_DATATYPE_INVALIDE,
} PWR_COM_COL_DATATYPE;

typedef struct PWR_COM_CallbackData {
    char ctime[PWR_MAX_TIME_LEN];
    PWR_COM_COL_DATATYPE dataType;
    int dataLen;
    char data[0];
} PWR_COM_CallbackData;

typedef struct PWR_COM_BasicDcTaskInfo {
    PWR_COM_COL_DATATYPE dataType;
    int interval;
} PWR_COM_BasicDcTaskInfo;

typedef enum PWR_COM_EVT_TYPE {
    PWR_COM_EVTTYPE_CPUFREQ_GOV_CHANGED = 1,
    PWR_COM_EVTTYPE_AUTH_REQUESTED,
    PWR_COM_EVTTYPE_AUTH_RELEASED,
    PWR_COM_EVTTYPE_CRED_FAILED,
} PWR_COM_EVT_TYPE;

typedef struct PWR_COM_EventInfo {
    char ctime[PWR_MAX_TIME_LEN];
    PWR_COM_EVT_TYPE eventType;
    int infoLen;
    char info[0];
} PWR_COM_EventInfo;

typedef struct PWR_SYS_PowerInfo {
    int sysPower;
    int cpuPower;
    int memPower;
} PWR_SYS_PowerInfo;

typedef struct PWR_SYS_StatisticPowerInfo {
    int maxSysPower;
    int avgSysPower;
    double totalEnergy;
    char maxSysPowerTime[PWR_MAX_TIME_LEN];
    char startTime[PWR_MAX_TIME_LEN];
} PWR_SYS_StatisticPowerInfo;

typedef struct PWR_CPU_NumaInfo {
    int nodeNo;
    char cpuList[PWR_MAX_CPU_LIST_LEN];
} PWR_CPU_NumaInfo;

typedef struct PWR_CPU_Info {
    char arch[PWR_MAX_ELEMENT_NAME_LEN];
    char modelName[PWR_MAX_NAME_LEN];
    int byteOrder;
    int coreNum;
    char onlineList[PWR_MAX_CPU_LIST_LEN];
    int threadsPerCore;
    int coresperSocket;
    double maxFreq;
    double minFreq;
    int numaNum;
    PWR_CPU_NumaInfo numa[PWR_MAX_NUMA_NODE_NUM];
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

typedef struct PWR_CPU_PerfData {
    double ipc;
    double llcMiss;
} PWR_CPU_PerfData;

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
    char curDriver[PWR_MAX_ELEMENT_NAME_LEN];
    int avGovNum;
    char avGovList[PWR_MAX_GOV_NUM][PWR_MAX_ELEMENT_NAME_LEN];
    int freqDomainNum;
    int freqDomainStep;
    char freqDomain[0];
} PWR_CPU_FreqAbility;

typedef struct PWR_COM_Attr {
    char key[PWR_MAX_ELEMENT_NAME_LEN];
    char value[PWR_MAX_VALUE_LEN];
} PWR_COM_Attr;

typedef struct PWR_CPU_FreqGovAttr {
    char gov[PWR_MAX_ELEMENT_NAME_LEN];
    PWR_COM_Attr attr;
} PWR_CPU_FreqGovAttr;

typedef struct PWR_CPU_FreqGovAttrs {
    char gov[PWR_MAX_ELEMENT_NAME_LEN];
    PWR_COM_Attr attrs[PWR_MAX_GOV_ATTR_NUM];
    uint32_t attrNum;
} PWR_CPU_FreqGovAttrs;

typedef struct PWR_CPU_FreqRange {
    int minFreq;
    int maxFreq;
} PWR_CPU_FreqRange;

typedef struct PWR_CPU_CurFreq {
    int policyId;
    double curFreq;
} PWR_CPU_CurFreq;

typedef  struct PWR_CPU_Cstate {
    int id;
    int disable;
    uint32_t latency;
    char name[PWR_MAX_ELEMENT_NAME_LEN];
} PWR_CPU_Cstate;

typedef struct PWR_CPU_IdleInfo {
    char currDrv[PWR_MAX_ELEMENT_NAME_LEN];
    char currGov[PWR_MAX_ELEMENT_NAME_LEN];
    char avGovs[PWR_MAX_IDLE_GOV_NUM][PWR_MAX_ELEMENT_NAME_LEN];
    uint32_t cstateNum;
    PWR_CPU_Cstate cstates[0];
} PWR_CPU_IdleInfo;

typedef struct PWR_NET_Eth {
    char ethName[PWR_MAX_ELEMENT_NAME_LEN];
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
    char diskId[PWR_MAX_ELEMENT_NAME_LEN];
} PWR_DISK_Info;

typedef struct PWR_DISK_Load {
    char diskId[PWR_MAX_ELEMENT_NAME_LEN];
    uint32_t rLoad;
    uint32_t wLoad;
} PWR_DISK_Load;

typedef struct PWR_DISK_PwrLevel {
    char diskId[PWR_MAX_ELEMENT_NAME_LEN];
    uint16_t powerLevel;
    uint16_t spindownLevel;
} PWR_DISK_PwrLevel;

typedef struct PWR_DISK_ScsiPolicy {
    char scsiId[PWR_MAX_ELEMENT_NAME_LEN];
    int alpm;
} PWR_DISK_ScsiPolicy;

// USB
typedef struct PWR_USB_AutoSuspend {
    char usbId[PWR_MAX_ELEMENT_NAME_LEN];
    int control;
    int autoSuspendDelay;
    int wakeup;
} PWR_USB_AutoSuspend;

typedef struct PWR_PROC_WattAttrs {
    int scaleThreshold;
    int domainMask;
    int scaleInterval;
    char reserved[PWR_INIT_RESERVED_LEN];
} PWR_PROC_WattAttrs;

typedef struct PWR_PROC_SmartGridProcs {
    PWR_PROC_SMART_GRID_LEVEL level;
    int procNum;
    pid_t procs[0];
} PWR_PROC_SmartGridProcs;

typedef struct PWR_PROC_SmartGridGov {
    int sgAgentState;
    char sgLevel0Gov[PWR_MAX_ELEMENT_NAME_LEN];
    char sgLevel1Gov[PWR_MAX_ELEMENT_NAME_LEN];
} PWR_PROC_SmartGridGov;

typedef struct PWR_PROC_ServiceStatus {
    PWR_PROC_SERVICE_NAME name;
    PWR_PROC_SERVICE_STATUS status;
} PWR_PROC_ServiceStatus;

typedef struct PWR_PROC_ServiceState {
    PWR_PROC_SERVICE_NAME name;
    int state;
} PWR_PROC_ServiceState;

// HBM
typedef enum PWR_HBM_SYS_STATE {
    PWR_HBM_NOT_SUPPORT = 0,
    PWR_HBM_FLAT_MOD,
    PWR_HBM_CACHE_MOD,
    PWR_HBM_HYBRID_MOD,
} PWR_HBM_SYS_STATE;

#endif