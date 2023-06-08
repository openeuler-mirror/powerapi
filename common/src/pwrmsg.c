/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022 All rights reserved.
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
 * Description: Message struct and operations implementation. These messages used for communication between
 * PowerAPI.so and PowerAPI service.
 * **************************************************************************** */
#include "pwrmsg.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pwrerr.h"

static pid_t g_pid = 0;
static pthread_mutex_t g_seqLock;

static uint32_t GenerateSeqId()
{
    static uint16_t seed = 0;
    uint32_t pid = g_pid << 16;
    pthread_mutex_lock((pthread_mutex_t *)&g_seqLock);
    uint32_t seqId = pid + seed;
    seed++;
    pthread_mutex_unlock((pthread_mutex_t *)&g_seqLock);
    return seqId;
}

static uint32_t GenerateCrcMagic()
{
    // todo
    return 0;
}

static int GenerateReqMsgHead(MsgHead *head, enum OperationType optType, uint32_t taskNo, uint32_t dataLen)
{
    if (!head) {
        return ERR_NULL_POINTER;
    }
    bzero(head, sizeof(MsgHead));
    head->majorVer = MAJOR_VERSION;
    head->minorVer = MINOR_VERSION;
    head->optType = optType;
    head->dataFormat = FMT_BIN;
    head->msgType = MT_REQ;
    head->rspCode = 0;
    head->seqId = GenerateSeqId();
    head->taskNo = taskNo;
    head->crcMagic = GenerateCrcMagic();
    head->dataLen = dataLen;
    head->sysId = (uint32_t)g_pid;
    return SUCCESS;
}

PwrMsg *CreateReqMsg(enum OperationType optType, uint32_t taskNo, uint32_t dataLen, char *data)
{
    PwrMsg *req = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!req) {
        return NULL;
    }

    bzero(req, sizeof(PwrMsg));
    req->data = data;
    GenerateReqMsgHead(&req->head, optType, taskNo, dataLen);
    return req;
}

PwrMsg *ClonePwrMsg(PwrMsg *msg)
{
    if (!msg) {
        return NULL;
    }
    PwrMsg *c = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!c) {
        return NULL;
    }
    c->head = msg->head;
    c->data = NULL;
    if (msg->data) {
        char *data = (char *)malloc(msg->head.dataLen);
        if (!data) {
            free(c);
            return NULL;
        }
        memcpy(data, msg->data, msg->head.dataLen);
        c->data = data;
    }
    return c;
}

int InitMsgFactory(void)
{
    g_pid = getpid();
    pthread_mutex_init((pthread_mutex_t *)&g_seqLock, NULL);
}

void DestroyMsgFactory(void)
{
    pthread_mutex_destroy((pthread_mutex_t *)&g_seqLock);
}

int GenerateMetadataMsg(PwrMsg *metadata, uint32_t sysId, char *data, uint32_t len)
{
    if (!metadata || !data) {
        return ERR_NULL_POINTER;
    }
    bzero(metadata, sizeof(PwrMsg));
    metadata->head.majorVer = MAJOR_VERSION;
    metadata->head.minorVer = MINOR_VERSION;
    metadata->head.optType = COM_CALLBACK_DATA;
    metadata->head.dataFormat = FMT_BIN;
    metadata->head.msgType = MT_MDT;
    metadata->head.rspCode = 0;
    metadata->head.seqId = GenerateSeqId();
    metadata->head.taskNo = 0;  // Currently ineffective
    metadata->head.crcMagic = GenerateCrcMagic();
    metadata->head.dataLen = len;
    metadata->head.sysId = sysId;
    metadata->data = data;
}

int GenerateRspMsg(const PwrMsg *req, PwrMsg *rsp, int rspCode, char *data, int dataLen)
{
    if (!req || !rsp) {
        return ERR_NULL_POINTER;
    }

    bzero(rsp, sizeof(PwrMsg));
    rsp->head.majorVer = req->head.majorVer;
    rsp->head.minorVer = req->head.minorVer;
    rsp->head.optType = req->head.optType;
    rsp->head.dataFormat = FMT_BIN;
    rsp->head.msgType = MT_RSP;
    rsp->head.rspCode = rspCode;
    rsp->head.seqId = req->head.seqId;
    rsp->head.taskNo = req->head.taskNo;
    rsp->head.crcMagic = GenerateCrcMagic();
    rsp->head.dataLen = dataLen;
    rsp->head.sysId = req->head.sysId;
    rsp->data = data;
    return SUCCESS;
}

void InitThreadInfo(ThreadInfo *threadInfo)
{
    if (!threadInfo) {
        return;
    }
    threadInfo->keepRunning = TRUE;
    threadInfo->created = FALSE;
    threadInfo->tid = 0;
}

int CreateThread(ThreadInfo *threadInfo, void *(*thread_proc)(void *), void *arg)
{
    if (!threadInfo || !thread_proc) {
        return ERR_NULL_POINTER;
    }
    threadInfo->keepRunning = TRUE;
    if (pthread_create(&threadInfo->tid, NULL, thread_proc, arg) != SUCCESS) {
        return ERR_SYS_EXCEPTION;
    }
    threadInfo->created = TRUE;
    return SUCCESS;
}

void FiniThreadInfo(ThreadInfo *threadInfo)
{
    if (!threadInfo) {
        return;
    }
    threadInfo->keepRunning = FALSE;
    if (threadInfo->created == TRUE) {
        pthread_join(threadInfo->tid, NULL);
    }
    threadInfo->created = FALSE;
}