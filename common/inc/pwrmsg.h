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
 * Description: Message struct and operations definition. These messages used for communication between
 * PowerAPI.so and PowerAPI service.
 * **************************************************************************** */
#ifndef __POWERAPI_PROTOCOL_H__
#define __POWERAPI_PROTOCOL_H__

#include "pwrerr.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

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
    uint32_t sysId; // 消息源头的系统标识，IPC场景使用PID
    char reserved[4];
} MsgHead;

typedef struct PwrMsg {
    MsgHead head;
    char *data;
} PwrMsg;

enum OperationType {
    CPU_GET_INFO = 1,
    CPU_GET_USAGE,
    CPU_GET_CACHE_MISS,
    CPU_GET_FREQ_ABILITY,
    CPU_GET_FREQ_GOVERNOR,
    CPU_SET_FREQ_GOVERNOR,
    CPU_GET_DMA_LATENCY,
    CPU_SET_DMA_LATENCY,
    DISK_GET_IO_RATE = 30,
    // todo
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
int InitMsgFactory();
void DestroyMsgFactory();
int GenerateRspMsg(PwrMsg *req, PwrMsg *rsp, int rspCode, char *data, int dataLen);

#define TRUE 1
#define FALSE 0
typedef struct ThreadInfo {
    pthread_t tid;
    int keepRunning;
    int created;
} ThreadInfo;

void InitThreadInfo(ThreadInfo *threadInfo);
int CreateThread(ThreadInfo *threadInfo, void *(*thread_proc)(void *));
void FiniThreadInfo(ThreadInfo *threadInfo);

#endif
