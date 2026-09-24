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
#include "hbmservice.h"
#include "pwrbuffer.h"
#include "pwrerr.h"
#include "log.h"

static pthread_mutex_t g_hbmLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hbmCond = PTHREAD_COND_INITIALIZER;
static pthread_t g_hbmThread;
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
        pthread_mutex_unlock(&g_hbmLock);
        Logger(DEBUG, MD_NM_SVR_HBM, "HBM worker request start. opt:%u, sysId:%u, seqId:%u",
            req->head.optType, req->head.sysId, req->head.seqId);
        /* The synchronous handler owns its task context and sends one response. */
        SetHbmAllPowerState(req);
        ReleasePwrMsg(&req);
        pthread_mutex_lock(&g_hbmLock);
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
    int ret = pthread_create(&g_hbmThread, NULL, RunHbmWorker, NULL);
    if (ret != 0) {
        g_hbmRunning = 0;
        pthread_mutex_unlock(&g_hbmLock);
        Logger(ERROR, MD_NM_SVR_HBM, "Failed to create HBM worker. ret:%d", ret);
        return PWR_ERR_SYS_EXCEPTION;
    }
    g_hbmCreated = 1;
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
    pthread_mutex_lock(&g_hbmLock);
    g_hbmCreated = 0;
    pthread_mutex_unlock(&g_hbmLock);
}
