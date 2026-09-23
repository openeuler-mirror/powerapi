/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangyi
 * Create: 2026-09-17
 * Description: implement the HBM request worker
 * **************************************************************************** */
#include "hbmworker.h"
#include <time.h>
#include "hbmservice.h"
#include "pwrbuffer.h"
#include "pwrerr.h"
#include "log.h"
#include "hbmtask.h"
#include "server.h"

#define WATCHDOG_POLL_NS 50000000L

static pthread_mutex_t g_hbmLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hbmCond = PTHREAD_COND_INITIALIZER;
static pthread_t g_hbmThread;
static pthread_t g_watchdogThread;
static HbmTask *g_activeTask;
static PwrMsg *g_activeRequest;
static int g_activeResponded;
static int g_hbmUnavailable;
static int g_hbmCreated;
static int g_hbmRunning;
static PwrMsg *g_hbmQueue[PWR_BUFFER_SIZE];
static size_t g_hbmHead;
static size_t g_hbmCount;

static PwrMsg *PopHbmRequest(void)
{
    PwrMsg *req = g_hbmQueue[g_hbmHead];
    g_hbmQueue[g_hbmHead] = NULL;
    g_hbmHead = (g_hbmHead + 1) % PWR_BUFFER_SIZE;
    g_hbmCount--;
    return req;
}

/* Caller holds g_hbmLock. Reject pending work before another task can start. */
static void RejectPendingHbmRequests(void)
{
    g_hbmUnavailable = 1;
    while (g_hbmCount) {
        PwrMsg *req = PopHbmRequest();
        SendRspToClient(req, PWR_ERR_HBM_STATE_UNKNOWN, NULL, 0);
        ReleasePwrMsg(&req);
    }
}

/* g_hbmLock protects the active task lifetime and the single response decision. */
static void ReportTimeout(void)
{
    g_hbmUnavailable = 1;
    g_activeResponded = 1;
    SendRspToClient(g_activeRequest, PWR_ERR_HBM_OPERATION_TIMEOUT, NULL, 0);
    MsgHead request = g_activeRequest->head;
    RejectPendingHbmRequests();
    HbmTaskSnapshot snapshot;
    int snapshotRet = SnapshotHbmTask(g_activeTask, &snapshot);
    // The deep copy outlives the task. Do not block queue rejection on progress logging.
    pthread_mutex_unlock(&g_hbmLock);
    if (snapshotRet == PWR_SUCCESS) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long long nowUs = now.tv_sec * 1000000LL + now.tv_nsec / 1000;
        Logger(ERROR, MD_NM_SVR_HBM,
            "HBM task timeout. opt:%u, sysId:%u, seqId:%u, state:%d, phase:%s, node:%s, block:%s, "
            "elapsedMs:%lld, phaseElapsedMs:%lld, timeoutMs:%lld, "
            "hbmState:unknown, kernelOperation:may_still_be_running",
            snapshot.request.optType, snapshot.request.sysId, snapshot.request.seqId, snapshot.powerState,
            snapshot.phase, snapshot.node, snapshot.block,
            (nowUs - snapshot.startUs) / MICROSECONDS_PER_MILLISECOND,
            (nowUs - snapshot.phaseStartUs) / MICROSECONDS_PER_MILLISECOND,
            HBM_TASK_TIMEOUT_US / MICROSECONDS_PER_MILLISECOND);
        for (size_t i = 0; i < snapshot.progressCount; i++) {
            HbmProgress *p = &snapshot.progress[i];
            Logger(ERROR, MD_NM_SVR_HBM,
                "HBM timeout progress. sysId:%u, seqId:%u, node:%s, block:%s, completed:%d, "
                "alreadyOffline:%d",
                snapshot.request.sysId, snapshot.request.seqId, p->node, p->block,
                p->completed, p->alreadyOffline);
        }
        FreeHbmTaskSnapshot(&snapshot);
    } else {
        Logger(ERROR, MD_NM_SVR_HBM, "HBM timeout snapshot failed. sysId:%u, seqId:%u, hbmState:unknown",
            request.sysId, request.seqId);
    }
    pthread_mutex_lock(&g_hbmLock);
}

static void *RunHbmWatchdog(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_hbmLock);
        if (!g_hbmRunning && !g_activeTask) {
            pthread_mutex_unlock(&g_hbmLock);
            return NULL;
        }
        if (g_activeTask && !g_activeResponded && IsHbmTaskTimedOut(g_activeTask)) {
            ReportTimeout();
        }
        pthread_mutex_unlock(&g_hbmLock);
        struct timespec interval = {.tv_nsec = WATCHDOG_POLL_NS};
        nanosleep(&interval, NULL);
    }
}

/* Caller holds g_hbmLock; ReportTimeout temporarily releases and reacquires it. */
static void ReplyCompletedHbmTask(PwrMsg *req, HbmTask *task, int ret)
{
    if (g_activeResponded) {
        return;
    }
    if (IsHbmTaskTimedOut(task)) {
        ReportTimeout();
        return;
    }

    g_activeResponded = 1;
    SendRspToClient(req, ret, NULL, 0);
}

static void *RunHbmWorker(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_hbmLock);
    for (;;) {
        while (g_hbmRunning && g_hbmCount == 0) {
            pthread_cond_wait(&g_hbmCond, &g_hbmLock);
        }
        if (!g_hbmRunning) {
            break;
        }
        PwrMsg *req = PopHbmRequest();
        HbmTask *task = CreateHbmTask(req);
        if (!task) {
            int ret = (!req->data || req->head.dataLen != sizeof(HbmPowerStateRequest)) ?
                PWR_ERR_INVALIDE_PARAM : PWR_ERR_COMMON;
            SendRspToClient(req, ret, NULL, 0);
            ReleasePwrMsg(&req);
            continue;
        }
        g_activeTask = task;
        g_activeRequest = req;
        g_activeResponded = 0;
        pthread_mutex_unlock(&g_hbmLock);
        Logger(DEBUG, MD_NM_SVR_HBM, "HBM worker request start. opt:%u, sysId:%u, seqId:%u",
            req->head.optType, req->head.sysId, req->head.seqId);
        int ret = ExecuteHbmPowerTask(task);
        pthread_mutex_lock(&g_hbmLock);
        ReplyCompletedHbmTask(req, task, ret);
        Logger(DEBUG, MD_NM_SVR_HBM,
            "HBM worker request finish. sysId:%u, seqId:%u, ret:%d, hbmUnavailable:%d",
            req->head.sysId, req->head.seqId, ret, g_hbmUnavailable);
        g_activeTask = NULL;
        g_activeRequest = NULL;
        DestroyHbmTask(task);
        ReleasePwrMsg(&req);
    }
    pthread_mutex_unlock(&g_hbmLock);
    return NULL;
}

int StartHbmWorker(void)
{
    pthread_mutex_lock(&g_hbmLock);
    if (g_hbmCreated) {
        pthread_mutex_unlock(&g_hbmLock);
        return PWR_ERR_COMMON;
    }
    g_hbmHead = 0;
    g_hbmCount = 0;
    g_hbmRunning = 1;
    g_hbmUnavailable = 0;
    int ret = pthread_create(&g_hbmThread, NULL, RunHbmWorker, NULL);
    if (ret != 0) {
        g_hbmRunning = 0;
        pthread_mutex_unlock(&g_hbmLock);
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to create HBM worker. ret:%d", ret);
        return PWR_ERR_SYS_EXCEPTION;
    }
    g_hbmCreated = 1;
    ret = pthread_create(&g_watchdogThread, NULL, RunHbmWatchdog, NULL);
    if (ret != 0) {
        g_hbmRunning = 0;
        pthread_cond_broadcast(&g_hbmCond);
        pthread_mutex_unlock(&g_hbmLock);
        pthread_join(g_hbmThread, NULL);
        pthread_mutex_lock(&g_hbmLock);
        g_hbmCreated = 0;
        pthread_mutex_unlock(&g_hbmLock);
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to create HBM watchdog. ret:%d", ret);
        return PWR_ERR_SYS_EXCEPTION;
    }
    pthread_mutex_unlock(&g_hbmLock);
    return PWR_SUCCESS;
}

int SubmitHbmRequest(PwrMsg *req)
{
    if (!req || req->head.optType != HBM_SET_ALL_POWER_STATE) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    pthread_mutex_lock(&g_hbmLock);
    int ret = PWR_SUCCESS;
    if (!g_hbmRunning) {
        ret = PWR_ERR_SYS_EXCEPTION;
    } else if (g_hbmUnavailable) {
        ret = PWR_ERR_HBM_STATE_UNKNOWN;
    } else if (g_hbmCount == PWR_BUFFER_SIZE - 1) {
        ret = PWR_ERR_MSG_BUFFER_FULL;
    } else {
        size_t tail = (g_hbmHead + g_hbmCount) % PWR_BUFFER_SIZE;
        g_hbmQueue[tail] = req;
        g_hbmCount++;
        pthread_cond_signal(&g_hbmCond);
    }
    pthread_mutex_unlock(&g_hbmLock);
    return ret;
}

void StopHbmWorker(void)
{
    pthread_mutex_lock(&g_hbmLock);
    if (!g_hbmCreated) {
        pthread_mutex_unlock(&g_hbmLock);
        return;
    }
    g_hbmRunning = 0;
    while (g_hbmCount) {
        PwrMsg *req = PopHbmRequest();
        ReleasePwrMsg(&req);
    }
    pthread_cond_broadcast(&g_hbmCond);
    pthread_mutex_unlock(&g_hbmLock);
    pthread_join(g_hbmThread, NULL);
    pthread_join(g_watchdogThread, NULL);
    pthread_mutex_lock(&g_hbmLock);
    g_hbmCreated = 0;
    pthread_mutex_unlock(&g_hbmLock);
}
