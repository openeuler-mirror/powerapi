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
 * Description: Message struct and operations definition. These messages used for communication between
 * PowerAPI.so and PowerAPI service.
 * **************************************************************************** */
#ifndef POWERAPI_PROTOCOL_H__
#define POWERAPI_PROTOCOL_H__

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include "pwrdata.h"

#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define MAX_DATA_SIZE 4096

typedef struct MsgHead {
    uint8_t majorVer;
    uint8_t minorVer;
    uint16_t optType;
    uint8_t dataFormat;
    uint8_t msgType;
    uint16_t rspCode;
    uint32_t seqId;
    uint32_t taskNo;
    uint32_t crcMagic;
    uint32_t dataLen;
    uint32_t sysId; // System id of msg source, using PID for IPC scene.
    char reserved[4];
} MsgHead;

typedef struct PwrMsg {
    MsgHead head;
    char *data;
} PwrMsg;

enum OperationType {
    COM_CREATE_DC_TASK = 10,
    COM_DELETE_DC_TASK,
    COM_CALLBACK_DATA,
    COM_CALLBACK_EVENT,
    COM_REQUEST_CONTROL_AUTH,
    COM_RELEASE_CONTROL_AUTH,
    SYS_SET_POWER_STATE = 100,
    SYS_GET_CAPPED_POWER,
    SYS_SET_CAPPED_POWER,
    SYS_GET_RT_POWER,
    SYS_GET_STC_POWER,
    CPU_GET_INFO = 200,
    CPU_GET_USAGE,
    CPU_GET_PERF_DATA,
    CPU_GET_FREQ_ABILITY,
    CPU_GET_FREQ_RANGE,
    CPU_SET_FREQ_RANGE,
    CPU_GET_FREQ_GOVERNOR,
    CPU_SET_FREQ_GOVERNOR,
    CPU_GET_FREQ_GOV_ATTRS,
    CPU_GET_FREQ_GOV_ATTR,
    CPU_SET_FREQ_GOV_ATTR,
    CPU_GET_CUR_FREQ,
    CPU_SET_CUR_FREQ,
    CPU_GET_IDLE_INFO,
    CPU_GET_IDLE_GOV,
    CPU_SET_IDLE_GOV,
    CPU_GET_DMA_LATENCY,
    CPU_SET_DMA_LATENCY,
    DISK_GET_IO_RATE = 300,
    DISK_GET_LIST,
    DISK_GET_LOAD,
    DISK_GET_POWER_LEVEL,
    DISK_SET_POWER_LEVEL,
    DISK_GET_SCSI_POLICY,
    DISK_SET_SCSI_POLICY,
    NET_GET_INFO = 400,
    NET_GET_THROUGH,
    NET_GET_SPEED_MOD,
    NET_SET_SPEED_MOD,
    USB_GET_AUTO_SUSPEND = 500,
    USB_SET_AUTO_SUSPEND,
    PROC_QUERY_PROCS = 600,
    PROC_GET_WATT_STATE,
    PROC_SET_WATT_STATE,
    PROC_GET_WATT_ARRTS,
    PROC_SET_WATT_ARRTS,
    PROC_GET_WATT_PROCS,
    PROC_ADD_WATT_PROCS,
    PROC_DEL_WATT_PROCS,
    PROC_GET_SMART_GRID_STATE,
    PROC_SET_SMART_GRID_STATE,
    PROC_GET_SMART_GRID_PROCS,
    PROC_SET_SMART_GRID_PROCS_LEVEL,
    PROC_GET_SMART_GRID_GOV,
    PROC_SET_SMART_GRID_GOV,
};
enum DataFormat {
    FMT_BIN = 0,
};
enum MsgType {
    MT_REQ = 1, // Request message
    MT_RSP,     // Response message
    MT_EVT,     // event notification
    MT_MDT      // metadata
};

static inline void ReleasePwrMsg(PwrMsg **msg)
{
    if (msg == NULL || *msg == NULL) {
        return;
    }
    free((*msg)->data);
    (*msg)->data = NULL;
    free(*msg);
    *msg = NULL;
}

PwrMsg *ClonePwrMsg(PwrMsg *msg);
PwrMsg *CreateReqMsg(enum OperationType optType, uint32_t taskNo, uint32_t dataLen, char *data);
int InitMsgFactory(void);
void DestroyMsgFactory(void);
int GenerateMetadataMsg(PwrMsg *metadata, uint32_t sysId, char *data, uint32_t len);
int GenerateRspMsg(const PwrMsg *req, PwrMsg *rsp, int rspCode, char *data, int dataLen);
int GenerateEventMsg(PwrMsg *event, uint32_t sysId, char *data, uint32_t len);

typedef struct ThreadInfo {
    pthread_t tid;
    int keepRunning;
    int created;
} ThreadInfo;

void InitThreadInfo(ThreadInfo *threadInfo);
int CreateThread(ThreadInfo *threadInfo, void *(*thread_proc)(void *), void *arg);
void FiniThreadInfo(ThreadInfo *threadInfo);

#endif