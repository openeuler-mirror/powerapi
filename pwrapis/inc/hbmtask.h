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
 * Description: provide HBM task lifecycle and progress interfaces
 * **************************************************************************** */
#ifndef PAPIS_HBM_TASK_H
#define PAPIS_HBM_TASK_H

#include "pwrmsg.h"
#include "utils.h"

/* Historical progress: distinguish pre-existing offline blocks from writes by this task. */
typedef struct {
    char node[MAX_FULL_NAME];
    char block[PWR_MAX_NAME_LEN]; /* Empty for a completed node. */
    int alreadyOffline;
    int completed;
    int restored;
} HbmProgress;

typedef struct {
    MsgHead request;
    int powerState;
    int started;
    int finished;
    int result;
    long long startUs; /* CLOCK_MONOTONIC, not wall time. */
    long long phaseStartUs;
    char phase[PWR_MAX_NAME_LEN];
    char node[MAX_FULL_NAME];
    char block[PWR_MAX_NAME_LEN];
    size_t progressCount;
    HbmProgress *progress;
} HbmTaskSnapshot;

typedef struct HbmTask HbmTask;

/* Copies request metadata and state; never retains or owns the caller's PwrMsg. */
HbmTask *CreateHbmTask(const PwrMsg *req);
/* Caller must ensure execution and all snapshot readers have stopped before destroying. */
void DestroyHbmTask(HbmTask *task);
int StartHbmTask(HbmTask *task);
void FinishHbmTask(HbmTask *task, int result);
void SetHbmTaskPhase(HbmTask *task, const char *phase, const char *node, const char *block);
int PrepareHbmProgress(HbmTask *task, const char *node, const char *block, size_t *index);
void CompleteHbmProgress(HbmTask *task, size_t index, int alreadyOffline);
void RestoreHbmProgress(HbmTask *task, const char *node, const char *block);
/* Snapshot owns a deep copy of progress; release it with FreeHbmTaskSnapshot. */
int SnapshotHbmTask(HbmTask *task, HbmTaskSnapshot *snapshot);
void FreeHbmTaskSnapshot(HbmTaskSnapshot *snapshot);
int ExecuteHbmPowerTask(HbmTask *task); /* Executes once; never sends a response. */

#endif
