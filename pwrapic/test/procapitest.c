/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: queyanwen
 * Create: 2023-10-25
 * Description: The testing of PowerAPI of PROC module.
 * **************************************************************************** */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "powerapi.h"

#define INVALIDE_STATE (-1)
static void TEST_PWR_PROC_SetAndGetWattState(void)
{
    int state = INVALIDE_STATE;
    int ret = PWR_SUCCESS;
    ret = PWR_PROC_GetWattState(&state);
    printf("PWR_PROC_GetWattState. ret: %d state:%d\n", ret, state);
    ret = PWR_PROC_SetWattState(PWR_ENABLE);
    printf("PWR_PROC_SetWattState. ret: %d state:%d\n", ret, state);
}

#define TEST_WATT_TH 60
#define TEST_WATT_IT 3000
#define TEST_WATT_DM 11

static void TEST_PWR_PROC_SetAndGetWattAttrs(void)
{
    int ret = PWR_SUCCESS;
    PWR_PROC_WattAttrs was = {0};
    ret = PWR_PROC_GetWattAttrs(&was);
    printf("PWR_PROC_GetWattAttrs: ret:%d th:%d, interval:%d dmask:%d\n", ret,
        was.scaleThreshold, was.scaleInterval, was.domainMask);
    was.scaleThreshold = TEST_WATT_TH;
    was.scaleInterval = TEST_WATT_IT;
    was.domainMask = TEST_WATT_DM;
    ret = PWR_PROC_SetWattAttrs(&was);
    if (ret != PWR_SUCCESS) {
        printf("PWR_PROC_SetWattAttrs: failed, ret: %d\n", ret);
        return;
    }
    bzero(&was, sizeof(was));
    (void)PWR_PROC_GetWattAttrs(&was);
    printf("PWR_PROC_SetWattAttrs: SUCCESS\n");
}

#define TEST_PID_NUM 2
#define TEST_PID_1 1
#define TEST_PID_2 2
static void TEST_PWR_PROC_AddAndDelWattProcs(void)
{
    // 1: pid 1
    // 2: pid 2
    pid_t procs[TEST_PID_NUM] = {TEST_PID_1, TEST_PID_2};
    int num = TEST_PID_NUM;
    int ret = PWR_PROC_AddWattProcs(procs, num);
    printf("PWR_PROC_AddWattProcs: ret:%d\n", ret);

    bzero(procs, sizeof(procs));
    ret = PWR_PROC_GetWattProcs(procs, &num);
    printf("PWR_PROC_GetWattProcs: ret:%d num:%d\n", ret, num);
    for (int i = 0; i < TEST_PID_NUM; i++) {
        printf("\tPWR_PROC_GetWattProcs. procs%d: %d.\n", i, procs[i]);
    }

    ret = PWR_PROC_DelWattProcs(procs, num - 1);
    printf("PWR_PROC_DelWattProcs: ret:%d\n", ret);
    bzero(procs, sizeof(procs));
    (void)PWR_PROC_GetWattProcs(procs, &num);
    for (int i = 0; i < num; i++) {
        printf("\tPWR_PROC_DelWattProcs. after del. procs%d: %d.\n", i, procs[i]);
    }
}

static void TEST_PWR_PROC_SetAndGetSmartGridState(void)
{
    int state = INVALIDE_STATE;
    int ret = PWR_SUCCESS;
    ret = PWR_PROC_GetSmartGridState(&state);
    printf("PWR_PROC_GetSmartGridState. ret: %d state:%d\n", ret, state);
    ret = PWR_PROC_SetSmartGridState(!state);
    printf("PWR_PROC_SetSmartGridState. ret: %d state:%d\n", ret, state);
}

static void TEST_PWR_PROC_SetAndGetSmartGridProcs(void)
{
    size_t size = sizeof(PWR_PROC_SmartGridProcs) + TEST_PID_NUM * sizeof(pid_t);
    PWR_PROC_SmartGridProcs *sgp = (PWR_PROC_SmartGridProcs *)malloc(size);
    if (!sgp) {
        return;
    }
    sgp->level = PWR_PROC_SG_LEVEL_1;
    sgp->procNum = TEST_PID_NUM;
    sgp->procs[0] = TEST_PID_1;
    sgp->procs[1] = TEST_PID_2;
    int ret = PWR_PROC_SetSmartGridLevel(sgp);
    printf("PWR_PROC_SetSmartGridLevel: ret:%d\n", ret);
    bzero(sgp, size);
    ret = PWR_PROC_GetSmartGridProcs(PWR_PROC_SG_LEVEL_1, sgp);
    printf("PWR_PROC_GetSmartGridProcs: ret:%d num:%d\n", ret, sgp->procNum);
    for (int i = 0; i < sgp->procNum; i++) {
        printf("\tPWR_PROC_GetSmartGridProcs, procId%d:%d\n", i, sgp->procs[i]);
    }
    free(sgp);
}

// public==============================================================================
void TEST_PROC_AllFunc(void)
{
    TEST_PWR_PROC_SetAndGetWattState();
    TEST_PWR_PROC_SetAndGetWattAttrs();
    TEST_PWR_PROC_AddAndDelWattProcs();
    TEST_PWR_PROC_SetAndGetSmartGridState();
    TEST_PWR_PROC_SetAndGetSmartGridProcs();
}