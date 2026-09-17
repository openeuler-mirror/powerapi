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
 * Description: implement HBM task lifecycle and progress tracking
 * **************************************************************************** */
#include "hbmtask.h"

#include <string.h>
#include <time.h>
#include "pwrerr.h"

#define MICROSECONDS_PER_SECOND 1000000LL
#define NANOSECONDS_PER_MICROSECOND 1000LL

struct HbmTask {
    pthread_mutex_t lock;
    HbmTaskSnapshot state;
};

static long long MonotonicUs(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * MICROSECONDS_PER_SECOND + now.tv_nsec / NANOSECONDS_PER_MICROSECOND;
}

static void CopyTaskString(char *dest, size_t destSize, const char *src)
{
    if (!dest || destSize == 0) {
        return;
    }

    size_t i = 0;
    if (src) {
        while (i + 1 < destSize && src[i] != '\0') {
            dest[i] = src[i];
            ++i;
        }
    }
    dest[i] = '\0';
}

HbmTask *CreateHbmTask(const PwrMsg *req)
{
    if (!req || !req->data || req->head.dataLen != sizeof(int)) {
        return NULL;
    }
    HbmTask *task = calloc(1, sizeof(*task));
    if (!task) {
        return NULL;
    }
    if (pthread_mutex_init(&task->lock, NULL) != 0) {
        free(task);
        return NULL;
    }
    task->state.request = req->head;
    task->state.powerState = *(const int *)req->data;
    return task;
}

void DestroyHbmTask(HbmTask *task)
{
    if (task) {
        free(task->state.progress);
        pthread_mutex_destroy(&task->lock);
        free(task);
    }
}

int StartHbmTask(HbmTask *task)
{
    pthread_mutex_lock(&task->lock);
    if (task->state.started) {
        pthread_mutex_unlock(&task->lock);
        return PWR_ERR_COMMON;
    }
    task->state.started = 1;
    task->state.startUs = MonotonicUs();
    pthread_mutex_unlock(&task->lock);
    return PWR_SUCCESS;
}

void FinishHbmTask(HbmTask *task, int result)
{
    pthread_mutex_lock(&task->lock);
    task->state.finished = 1;
    task->state.result = result;
    pthread_mutex_unlock(&task->lock);
}

void SetHbmTaskPhase(HbmTask *task, const char *phase, const char *node, const char *block)
{
    pthread_mutex_lock(&task->lock);
    CopyTaskString(task->state.phase, sizeof(task->state.phase), phase);
    CopyTaskString(task->state.node, sizeof(task->state.node), node);
    CopyTaskString(task->state.block, sizeof(task->state.block), block);
    task->state.phaseStartUs = MonotonicUs();
    pthread_mutex_unlock(&task->lock);
}

int PrepareHbmProgress(HbmTask *task, const char *node, const char *block, size_t *index)
{
    if (!task || !node || !index) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    if (strlen(node) >= MAX_FULL_NAME || (block && strlen(block) >= PWR_MAX_NAME_LEN)) {
        return PWR_ERR_COMMON;
    }
    pthread_mutex_lock(&task->lock);
    size_t count = task->state.progressCount;
    if (count >= SIZE_MAX / sizeof(HbmProgress)) {
        pthread_mutex_unlock(&task->lock);
        return PWR_ERR_COMMON;
    }
    HbmProgress *progress = malloc((count + 1) * sizeof(*progress));
    if (!progress) {
        pthread_mutex_unlock(&task->lock);
        return PWR_ERR_COMMON;
    }
    for (size_t i = 0; i < count; ++i) {
        progress[i] = task->state.progress[i];
    }
    progress[count] = (HbmProgress){0};
    CopyTaskString(progress[count].node, sizeof(progress[count].node), node);
    CopyTaskString(progress[count].block, sizeof(progress[count].block), block);
    free(task->state.progress);
    task->state.progress = progress;
    *index = count;
    task->state.progressCount++;
    pthread_mutex_unlock(&task->lock);
    return PWR_SUCCESS;
}

void CompleteHbmProgress(HbmTask *task, size_t index, int alreadyOffline)
{
    pthread_mutex_lock(&task->lock);
    task->state.progress[index].completed = 1;
    task->state.progress[index].alreadyOffline = alreadyOffline;
    pthread_mutex_unlock(&task->lock);
}

void RestoreHbmProgress(HbmTask *task, const char *node, const char *block)
{
    pthread_mutex_lock(&task->lock);
    for (size_t i = 0; i < task->state.progressCount; i++) {
        HbmProgress *p = &task->state.progress[i];
        if (strcmp(p->node, node) == 0 && strcmp(p->block, block ? block : "") == 0) {
            p->restored = 1;
        }
    }
    pthread_mutex_unlock(&task->lock);
}

int SnapshotHbmTask(HbmTask *task, HbmTaskSnapshot *snapshot)
{
    if (!task || !snapshot) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    *snapshot = (HbmTaskSnapshot){0};
    pthread_mutex_lock(&task->lock);
    HbmProgress *copy = NULL;
    if (task->state.progressCount) {
        size_t size = task->state.progressCount * sizeof(*copy);
        copy = malloc(size);
        if (!copy) {
            pthread_mutex_unlock(&task->lock);
            return PWR_ERR_COMMON;
        }
        for (size_t i = 0; i < task->state.progressCount; ++i) {
            copy[i] = task->state.progress[i];
        }
    }
    *snapshot = task->state;
    snapshot->progress = copy;
    pthread_mutex_unlock(&task->lock);
    return PWR_SUCCESS;
}

void FreeHbmTaskSnapshot(HbmTaskSnapshot *snapshot)
{
    free(snapshot->progress);
    snapshot->progress = NULL;
    snapshot->progressCount = 0;
}
