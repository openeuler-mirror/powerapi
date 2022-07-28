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
 * Description: Provide buffer struct and operations
 * **************************************************************************** */
#include "pwrbuffer.h"
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "pwrerr.h"

#define WAITING_RESULT_TIME_OUT 1 // second
#define USEC_TO_NSEC 1000
// queue private
static void DeleteFromHead(PwrMsgBuffer *smb)
{
    if (!IsEmptyBuffer(smb)) {
        int t = (smb->head + 1) % PWR_BUFFER_SIZE;
        ReleasePwrMsg(&(smb->msgList[t]));
        smb->head = t;
    }
}

// queue public=================================================================
void InitPwrMsgBuffer(PwrMsgBuffer *smb)
{
    if (!smb) {
        return;
    }
    bzero(smb, sizeof(PwrMsgBuffer));
    pthread_mutex_init((pthread_mutex_t *)&(smb->mutex), NULL);
}

void ResetPwrMsgBuffer(PwrMsgBuffer *smb)
{
    if (!smb) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t *)&(smb->mutex));
    for (int i = smb->head; i != smb->tail;) {
        ReleasePwrMsg(&smb->msgList[i]);
        i = (i + 1) % PWR_BUFFER_SIZE;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&(smb->mutex));
    pthread_mutex_destroy((pthread_mutex_t *)&(smb->mutex));
}

int AddToBufferTail(PwrMsgBuffer *smb, PwrMsg *newMsg)
{
    if (!smb || !newMsg) {
        return ERR_NULL_POINTER;
    }
    pthread_mutex_lock((pthread_mutex_t *)&(smb->mutex));
    int t = (smb->tail + 1) % PWR_BUFFER_SIZE;
    if (t == smb->head) { // the queue is full
        DeleteFromHead(smb);
    }
    smb->msgList[t] = newMsg;
    smb->tail = t;
    pthread_mutex_unlock((pthread_mutex_t *)&(smb->mutex));
    return 0;
}

PwrMsg *PopFromBufferHead(PwrMsgBuffer *smb)
{
    if (!smb) {
        return NULL;
    }
    PwrMsg *p = NULL;
    pthread_mutex_lock((pthread_mutex_t *)&(smb->mutex));
    if (!IsEmptyBuffer(smb)) {
        int t = (smb->head + 1) % PWR_BUFFER_SIZE;
        p = smb->msgList[t];
        smb->msgList[t] = NULL;
        smb->head = t;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&(smb->mutex));
    return p;
}

// list private======================================================================
static ResultWaitingMsgNode *MoveFromList(ResultWaitingMsgList *rwm, ResultWaitingMsgNode *node)
{
    if (!rwm || !node) {
        return NULL;
    }
    if (node == rwm->head && rwm->head == rwm->tail) {
        rwm->head = NULL;
        rwm->tail = NULL;
    } else if (node == rwm->head) {
        rwm->head = node->next;
        rwm->head->prev = NULL;
    } else if (node == rwm->tail) {
        rwm->tail = node->prev;
        rwm->tail->next = NULL;
    } else {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
    node->next = NULL;
    node->prev = NULL;
    return node;
}


// list public=======================================================================

ResultWaitingMsgNode *CreateResultWaitingMsgNode(void)
{
    ResultWaitingMsgNode *node = (ResultWaitingMsgNode *)malloc(sizeof(ResultWaitingMsgNode));
    if (!node) {
        return NULL;
    }
    bzero(node, sizeof(ResultWaitingMsgNode));
    pthread_mutex_init((pthread_mutex_t *)&(node->waitMutex), NULL);
    pthread_cond_init((pthread_cond_t *)&(node->waitCond), NULL);
    return node;
}

void ReleaseResultWaitingMsgNode(ResultWaitingMsgNode *node)
{
    if (!node) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t *)&(node->waitMutex));
    ReleasePwrMsg(&node->reqMsg);
    ReleasePwrMsg(&node->rspMsg);
    node->next = NULL;
    node->prev = NULL;
    pthread_cond_destroy((pthread_cond_t *)&(node->waitCond));
    pthread_mutex_unlock((pthread_mutex_t *)&(node->waitMutex));
    pthread_mutex_destroy((pthread_mutex_t *)&(node->waitMutex));
}

void InitResultWaitingList(ResultWaitingMsgList *rwm)
{
    if (!rwm) {
        return;
    }
    rwm->head = NULL;
    rwm->tail = NULL;
    pthread_mutex_init((pthread_mutex_t *)&(rwm->mutex), NULL);
}

void ResetResultWaitingList(ResultWaitingMsgList *rwm)
{
    if (!rwm) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t *)&(rwm->mutex));
    ResultWaitingMsgNode *pc = rwm->head;
    ResultWaitingMsgNode *pn = NULL;
    while (pc != NULL) {
        pn = pc->next;
        ReleaseResultWaitingMsgNode(pc);
        pc = pn;
    }
    rwm->head = NULL;
    rwm->tail = NULL;
    pthread_mutex_unlock((pthread_mutex_t *)&(rwm->mutex));
    pthread_mutex_destroy((pthread_mutex_t *)&(rwm->mutex));
}

void AddToWaitingListTail(ResultWaitingMsgList *rwm, ResultWaitingMsgNode *newNode)
{
    if (!rwm || !newNode) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t *)&(rwm->mutex));
    if (!rwm->tail || !rwm->head) { // first node
        rwm->head = newNode;
        rwm->tail = newNode;
        newNode->next = NULL;
        newNode->prev = NULL;
    } else {
        newNode->prev = rwm->tail;
        newNode->next = NULL;
        rwm->tail->next = newNode;
        rwm->tail = newNode;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&(rwm->mutex));
}


// find the node and move out from the list
// return: the pointer of the moved out node
ResultWaitingMsgNode *FindAndMoveWaitingMsg(ResultWaitingMsgList *rwm, uint32_t seqId)
{
    pthread_mutex_lock((pthread_mutex_t *)&(rwm->mutex));
    ResultWaitingMsgNode *r = NULL;
    ResultWaitingMsgNode *pc = rwm->head;
    while (pc) {
        if (pc->reqMsg != NULL && pc->reqMsg->head.seqId == seqId) {
            r = MoveFromList(rwm, pc);
            break;
        }
        pc = pc->next;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&(rwm->mutex));
    return r;
}

void MoveOutWaitingMsg(ResultWaitingMsgList *rwm, ResultWaitingMsgNode *node)
{
    if (!rwm || !node) {
        return;
    }
    ResultWaitingMsgNode *pc = rwm->head;
    pthread_mutex_lock((pthread_mutex_t *)&(rwm->mutex));
    while (pc) {
        if (pc == node) {
            MoveFromList(rwm, pc);
            break;
        }
        pc = pc->next;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&(rwm->mutex));
}

int WaitingForResponse(const ResultWaitingMsgNode *node)
{
    if (!node) {
        return ERR_NULL_POINTER;
    }
    struct timeval now;
    struct timespec outTime;
    pthread_mutex_lock((pthread_mutex_t *)&(node->waitMutex));
    gettimeofday(&now, NULL);
    outTime.tv_sec = now.tv_sec + WAITING_RESULT_TIME_OUT;
    outTime.tv_nsec = now.tv_usec * USEC_TO_NSEC;
    int ret =
        pthread_cond_timedwait((pthread_cond_t *)&(node->waitCond), (pthread_mutex_t *)&(node->waitMutex), &outTime);
    pthread_mutex_unlock((pthread_mutex_t *)&(node->waitMutex));
    if (ret == ETIMEDOUT) {
        return ERR_TIMEOUT;
    } else if (ret != 0) {
        return ERR_SYS_EXCEPTION;
    }
    return SUCCESS;
}
int DoRspToWaitingMsg(const ResultWaitingMsgNode *node)
{
    if (!node) {
        return ERR_NULL_POINTER;
    }
    pthread_mutex_lock((pthread_mutex_t *)&(node->waitMutex));
    pthread_cond_signal((pthread_cond_t *)&(node->waitCond));
    pthread_mutex_unlock((pthread_mutex_t *)&(node->waitMutex));
    return SUCCESS;
}