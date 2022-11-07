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
 * Create: 2022-11-05
 * Description: provide task service
 * **************************************************************************** */
// todo: socket断链时，需要考虑task的释放

#include "taskservice.h"
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "common.h"
#include "pwrerr.h"
#include "log.h"
#include "pwrdata.h"
#include "server.h"

#define INVALIDE_TASK_ID (-1)
#define MAX_TASK_NUM 10

typedef struct CollDataSubscriber {
    uint32_t sysId;
    int interval;
} CollDataSubscriber;


typedef struct CollTask {
    PWR_COM_COL_DATATYPE dataType;
    int interval;
    int subNum;                                        // 订阅数
    CollDataSubscriber subscriberList[MAX_CLIENT_NUM]; // 该数据订阅方
    ThreadInfo collThread;
} CollTask;

static CollTask *g_collTaskList[MAX_TASK_NUM];
static int g_taskNum = 0;
static pthread_mutex_t g_taskListMutex;
static int g_hasInited = FALSE;

static int FindCollTaskByType(PWR_COM_COL_DATATYPE dataType)
{
    if (g_taskNum == 0) {
        return INVALID_INDEX;
    }
    for (int i = 0; i < MAX_TASK_NUM; i++) {
        if (g_collTaskList[i] && g_collTaskList[i]->dataType == dataType) {
            return i;
        }
    }
    return INVALID_INDEX;
}

static int FindAvailebleTaskSlot(void)
{
    for (int i = 0; i < MAX_TASK_NUM; i++) {
        if (!g_collTaskList[i]) {
            return i;
        }
    }
    return INVALID_INDEX;
}

static inline void FiniTask(int index)
{
    FiniThreadInfo(&(g_collTaskList[index]->collThread)); // 必须先停止线程
    free(g_collTaskList[index]);
    g_collTaskList[index] = NULL;
    g_taskNum--;
}

// 需要使用指定的订阅者周期更新task周期时，subIdx填具体订阅者的索引，否则填INVALIDE_INDEX
static void UpdataTaskInterval(int index, int subIdx)
{
    if (subIdx != INVALID_INDEX) {
        if (g_collTaskList[index]->interval > g_collTaskList[index]->subscriberList[subIdx].interval) {
            g_collTaskList[index]->interval = g_collTaskList[index]->subscriberList[subIdx].interval;
        }
        return;
    }

    int interval = MAX_DC_INTERVAL;
    for (int i = 0; i < MAX_CLIENT_NUM; i++) {
        if (interval > g_collTaskList[index]->subscriberList[i].interval) {
            interval = g_collTaskList[index]->subscriberList[i].interval;
        }
    }
    g_collTaskList[index]->interval = interval;
}

static int FindSubscriberById(int index, uint32_t subscriber)
{
    for (int i = 0; i < MAX_CLIENT_NUM; i++) {
        if (g_collTaskList[index]->subscriberList[i].sysId == subscriber) {
            return i;
        }
    }
    return INVALID_INDEX;
}

static int AddSubscriber(int index, const PWR_COM_BasicDcTaskInfo *taskInfo, uint32_t subscriber)
{
    if (!g_collTaskList[index]) {
        return ERR_TASK_NOT_EXISTS;
    }
    int ret = SUCCESS;
    int subIdx = FindSubscriberById(index, subscriber);
    if (subIdx != INVALID_INDEX) {
        g_collTaskList[index]->subscriberList[subIdx].interval = taskInfo->interval;
        UpdataTaskInterval(index, subIdx);
    } else {
        int i;
        for (i = 0; i < MAX_CLIENT_NUM; i++) {
            if (g_collTaskList[index]->subscriberList[i].sysId == 0) { // find available subscriber sslot
                g_collTaskList[index]->subscriberList[i].sysId = subscriber;
                g_collTaskList[index]->subscriberList[i].interval = taskInfo->interval;
                g_collTaskList[index]->subNum++;
                UpdataTaskInterval(index, i);
                break;
            }
        }
        if (i == MAX_CLIENT_NUM) { // subscriber overflow
            ret = ERR_SYS_EXCEPTION;
        }
    }
    return ret;
}

static int DeleteSubscriber(int index, uint32_t subscriber)
{
    if (!g_collTaskList[index]) {
        return ERR_TASK_NOT_EXISTS;
    }
    for (int i = 0; i < MAX_CLIENT_NUM; i++) {
        if (g_collTaskList[index]->subscriberList[i].sysId == subscriber) {
            g_collTaskList[index]->subscriberList[i].sysId = 0;
            g_collTaskList[index]->subscriberList[i].interval = 0;
            g_collTaskList[index]->subNum--;
            break;
        }
    }

    if (g_collTaskList[index]->subNum <= 0) { // 无用户订阅数据时，停止采集
        FiniTask(index);
    } else {
        UpdataTaskInterval(index, INVALID_INDEX);
    }
    return SUCCESS;
}

typedef void (*ActionFunc)(CollTask *);

static void TaskProcessLlcMiss(CollTask *task)
{
    // todo: 采集LLC MISS 并发送
}
static void TaskProcessCpuUsage(CollTask *task)
{
    // todo: 采集CPU USAGE 并发送
}
static void TaskProcessCpuIpc(CollTask *task)
{
    // todo: 采集CPU IPC 并发送
}

static ActionFunc GetActionByDataType(PWR_COM_COL_DATATYPE dataType)
{
    switch (dataType) {
        case PWR_COM_DATATYPE_LLC_MISS:
            return TaskProcessLlcMiss;
        case PWR_COM_DATATYPE_CPU_USAGE:
            return TaskProcessCpuUsage;
        case PWR_COM_DATATYPE_CPU_IPC:
            return TaskProcessCpuIpc;
        default:
            return NULL;
    }
}

static void *RunDcTaskProcess(void *arg)
{
    CollTask *task = (CollTask *)arg;
    ActionFunc actionFunc = GetActionByDataType(task->dataType);
    if (!actionFunc) {
        return NULL;
    }

    while (task->collThread.keepRunning) {
        usleep(THOUSAND * (task->interval));
        actionFunc(task);
    }
}

static int CreateNewTask(const PWR_COM_BasicDcTaskInfo *taskInfo, uint32_t subscriber)
{
    int slot = FindAvailebleTaskSlot();
    if (slot == INVALID_INDEX) {
        return ERR_OVER_MAX_TASK_NUM;
    }

    CollTask *task = (CollTask *)malloc(sizeof(CollTask));
    if (!task) {
        return ERR_SYS_EXCEPTION;
    }
    bzero(task, sizeof(CollTask));
    task->dataType = taskInfo->dataType;
    task->interval = taskInfo->interval;
    task->subNum = 1;
    task->subscriberList[0].sysId = subscriber;
    task->subscriberList[0].interval = taskInfo->interval;
    InitThreadInfo(&(task->collThread));
    int rspCode = CreateThread(&(task->collThread), RunDcTaskProcess, (void *)task);
    if (rspCode != SUCCESS) {
        free(task);
        Logger(ERROR, MD_NM_SVR_TASK, "CreateNewTask failed. ret:%d type:%d, sysId:%d", rspCode, taskInfo->dataType,
            subscriber);
    } else {
        g_collTaskList[slot] = task;
        Logger(INFO, MD_NM_SVR_TASK, "CreateNewTask succeed. type:%d, sysId:%d", taskInfo->dataType, subscriber);
    }
    return rspCode;
}

// with lock================================================================

static int CreateTask(const PWR_COM_BasicDcTaskInfo *taskInfo, uint32_t subscriber)
{
    int rspCode = SUCCESS;
    pthread_mutex_lock(&g_taskListMutex);

    int index = FindCollTaskByType(taskInfo->dataType);
    if (index != INVALID_INDEX) { // task existed
        rspCode = AddSubscriber(index, taskInfo, subscriber);
    } else {
        rspCode = CreateNewTask(taskInfo, subscriber);
    }
    pthread_mutex_unlock(&g_taskListMutex);
    return rspCode;
}

static int DeleteTask(PWR_COM_COL_DATATYPE dataType, uint32_t subscriber)
{
    pthread_mutex_lock(&g_taskListMutex);
    int index = FindCollTaskByType(dataType);
    if (index != INVALID_INDEX) {
        DeleteSubscriber(index, subscriber);
    }
    pthread_mutex_unlock(&g_taskListMutex);
    return SUCCESS;
}

static void FiniAllTask(void)
{
    pthread_mutex_lock(&g_taskListMutex);
    for (int i = 0; i < MAX_TASK_NUM; i++) {
        if (g_collTaskList[i]) {
            FiniTask(i);
        }
    }
    pthread_mutex_unlock(&g_taskListMutex);
}


// public======================================================================
int InitTaskService(void)
{
    if (g_hasInited) {
        return SUCCESS;
    }
    bzero(g_collTaskList, MAX_TASK_NUM * sizeof(CollTask *));
    g_taskNum = 0;
    pthread_mutex_init((pthread_mutex_t *)&g_taskListMutex, NULL);
    g_hasInited = TRUE;
    return SUCCESS;
}


void FiniTaskService(void)
{
    FiniAllTask();
    g_taskNum = 0;
    pthread_mutex_destroy((pthread_mutex_t *)&g_taskListMutex);
    g_hasInited = FALSE;
}

void CreateDataCollTask(const PwrMsg *req)
{
    if (!req || req->head.dataLen != sizeof(PWR_COM_BasicDcTaskInfo)) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_TASK, "Get CreateDataCollTask Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);

    int rspCode = CreateTask((PWR_COM_BasicDcTaskInfo *)req->data, req->head.sysId);
    SendRspToClient(req, rspCode, NULL, 0);
}

void DeleteDataCollTask(const PwrMsg *req)
{
    if (!req || req->head.dataLen != sizeof(int)) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_TASK, "Get DeleteDataCollTask Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);

    PWR_COM_COL_DATATYPE *dataType = (PWR_COM_COL_DATATYPE *)req->data;
    int rspCode = DeleteTask(*dataType, req->head.sysId);
    SendRspToClient(req, rspCode, NULL, 0);
}