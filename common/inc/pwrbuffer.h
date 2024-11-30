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
 * Description: Provide buffer struct and operations
 * **************************************************************************** */
#ifndef POWERAPI_UTILS_H__
#define POWERAPI_UTILS_H__
#include <pthread.h>
#include "pwrmsg.h"

#define PWR_BUFFER_SIZE 256
// Ring Queue, FIFO
typedef struct PwrMsgBuffer {
    int head;
    int tail;
    pthread_mutex_t mutex;
    PwrMsg *msgList[PWR_BUFFER_SIZE];
} PwrMsgBuffer;

// List
struct __ResultWaitingMsgNode {
    pthread_mutex_t waitMutex;
    pthread_cond_t waitCond;
    struct __ResultWaitingMsgNode *next;
    struct __ResultWaitingMsgNode *prev;
    PwrMsg *reqMsg;
    PwrMsg *rspMsg;
};
typedef struct __ResultWaitingMsgNode ResultWaitingMsgNode;

typedef struct ResultWaitingMsgList {
    ResultWaitingMsgNode *head;
    ResultWaitingMsgNode *tail;
    pthread_mutex_t mutex;
} ResultWaitingMsgList;

void InitPwrMsgBuffer(PwrMsgBuffer *smb);
void ResetPwrMsgBuffer(PwrMsgBuffer *smb);
int AddToBufferTail(PwrMsgBuffer *smb, PwrMsg *newMsg);
PwrMsg *PopFromBufferHead(PwrMsgBuffer *smb);
static inline int IsEmptyBuffer(const PwrMsgBuffer *smb)
{
    if (!smb) {
        return 1;
    }
    return smb->head == smb->tail;
}
static inline int IsFullBuffer(const PwrMsgBuffer *smb)
{
    if (!smb) {
        return 0;
    }
    int t = (smb->tail + 1) % PWR_BUFFER_SIZE;
    return t == smb->head;
}

ResultWaitingMsgNode *CreateResultWaitingMsgNode(void);
void ReleaseResultWaitingMsgNode(ResultWaitingMsgNode *node);
void InitResultWaitingList(ResultWaitingMsgList *rwm);
void ResetResultWaitingList(ResultWaitingMsgList *rwm);
void AddToWaitingListTail(ResultWaitingMsgList *rwm, ResultWaitingMsgNode *newNode);
ResultWaitingMsgNode *FindAndMoveWaitingMsg(ResultWaitingMsgList *rwm, uint32_t seqId);
void MoveOutWaitingMsg(ResultWaitingMsgList *rwm, ResultWaitingMsgNode *node);
int WaitingForResponse(const ResultWaitingMsgNode *node);
int DoRspToWaitingMsg(const ResultWaitingMsgNode *node);

#endif
