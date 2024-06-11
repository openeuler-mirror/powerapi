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
#define TEST_MAX_PROC_NUM 100
static void TEST_PWR_PROC_QueryProcs(void)
{
    const char keywords[] = "nginx|mysql";
    pid_t procs[TEST_MAX_PROC_NUM] = {0};
    uint32_t num = TEST_MAX_PROC_NUM;
    int ret = PWR_PROC_QueryProcs(keywords, procs, &num);
    printf("PWR_PROC_QueryProcs. ret: %d num:%d\n", ret, num);
}

static void TEST_PWR_PROC_QueryProcs_LongKeywords(void)
{
    char keywords[PWR_MAX_STRING_LEN] = "/init|";
    for(int i = 6; i < PWR_MAX_STRING_LEN - 1; ++i)
    {
        keywords[i] = 'a';
    }
    pid_t procs[TEST_MAX_PROC_NUM] = {0};
    uint32_t num = TEST_MAX_PROC_NUM;
    int ret = PWR_PROC_QueryProcs(keywords, procs, &num);
    printf("PWR_PROC_QueryProcs. ret: %d num:%d\n", ret, num);
}

static void TEST_PWR_PROC_SetAndGetWattState(void)
{
    int state = INVALIDE_STATE;
    int ret = PWR_SUCCESS;
    ret = PWR_PROC_GetWattState(&state);
    printf("PWR_PROC_GetWattState. ret: %d state:%d\n", ret, state);
    ret = PWR_PROC_SetWattState(PWR_ENABLE);
    printf("PWR_PROC_SetWattState. ret: %d state:%d\n", ret, PWR_ENABLE);
    ret = PWR_PROC_SetWattState(PWR_DISABLE);
    printf("PWR_PROC_SetWattState. ret: %d state:%d\n", ret, PWR_DISABLE);
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
    printf("After PWR_PROC_SetWattAttrs: ret:%d th:%d, interval:%d dmask:%d\n", ret,
        was.scaleThreshold, was.scaleInterval, was.domainMask);
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
    for (int i = 0; i < num; i++) {
        printf("\tPWR_PROC_GetWattProcs. procs%d: %d.\n", i, procs[i]);
    }

    ret = PWR_PROC_DelWattProcs(procs, num);
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
    ret = PWR_PROC_SetSmartGridState(PWR_ENABLE);
    printf("PWR_PROC_SetSmartGridState. ret: %d\n", ret);
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
    sgp->procNum = TEST_PID_NUM;
    ret = PWR_PROC_GetSmartGridProcs(PWR_PROC_SG_LEVEL_1, sgp);
    printf("PWR_PROC_GetSmartGridProcs: ret:%d num:%d\n", ret, sgp->procNum);
    for (int i = 0; i < sgp->procNum; i++) {
        printf("\tPWR_PROC_GetSmartGridProcs, procId%d:%d\n", i, sgp->procs[i]);
    }
    free(sgp);
}

static void TEST_PWR_PROC_SetAndGetSmartGridGov(void)
{
    PWR_PROC_SmartGridGov sgGov = {0};
    int ret = PWR_PROC_GetSmartGridGov(&sgGov);
    printf("PWR_PROC_GetSmartGridGov: ret:%d sgAgentState:%d, sgLevel0Gov:%s sgLevel1Gov:%s\n",
        ret, sgGov.sgAgentState, sgGov.sgLevel0Gov, sgGov.sgLevel1Gov);

    const char level0Gov[] = "performance";
    const char level1Gov[] = "conservative";
    sgGov.sgAgentState = PWR_ENABLE;
    strncpy(sgGov.sgLevel0Gov, level0Gov, PWR_MAX_ELEMENT_NAME_LEN - 1);
    strncpy(sgGov.sgLevel1Gov, level1Gov, PWR_MAX_ELEMENT_NAME_LEN - 1);
    ret = PWR_PROC_SetSmartGridGov(&sgGov);
    bzero(&sgGov, sizeof(PWR_PROC_SmartGridGov));
    PWR_PROC_GetSmartGridGov(&sgGov);
    printf("PWR_PROC_SetSmartGridGov: ret:%d sgAgentState:%d, sgLevel0Gov:%s sgLevel1Gov:%s\n",
        ret, sgGov.sgAgentState, sgGov.sgLevel0Gov, sgGov.sgLevel1Gov);
}

static void TEST_PWR_PROC_SetWattFirstDomain(void)
{
    int cpuId = 0;
    int ret = PWR_PROC_SetWattFirstDomain(cpuId);
    printf("PWR_PROC_SetWattFirstDomain: ret:%d\n", ret);

    cpuId = 1234;
    ret = PWR_PROC_SetWattFirstDomain(cpuId);
    printf("PWR_PROC_SetWattFirstDomain: ret:%d\n", ret);

    cpuId = 23;
    ret = PWR_PROC_SetWattFirstDomain(cpuId);
    printf("PWR_PROC_SetWattFirstDomain: ret:%d\n", ret);

    ret = PWR_PROC_SetWattState(PWR_ENABLE);
    ret = PWR_PROC_SetWattFirstDomain(cpuId);
    printf("PWR_PROC_SetWattFirstDomain: ret:%d\n", ret);
}

static void TEST_PWR_PROC_GetServiceState(void)
{
    size_t size = sizeof(PWR_PROC_ServiceStatus);
    PWR_PROC_ServiceStatus sStatus = {0};
    sStatus.name = PWR_PROC_SERVICE_EAGLE;
    int ret = PWR_PROC_GetServiceState(&sStatus);
    printf("PWR_PROC_GetServiceState ret:%d status:%d\n", ret, sStatus.status);
}

static void TEST_PWR_PROC_SetServiceState(void)
{
    size_t size = sizeof(PWR_PROC_ServiceState);
    PWR_PROC_ServiceState sState = {0};
    sState.name = PWR_PROC_SERVICE_EAGLE;
    sState.state = PWR_SERVICE_START;
    int ret = PWR_PROC_SetServiceState(&sState);
    printf("PWR_PROC_SetServiceState ret:%d\n", ret);
}

// public==============================================================================
void TEST_PROC_AllFunc(void)
{
    TEST_PWR_PROC_QueryProcs();
    TEST_PWR_PROC_QueryProcs_LongKeywords();
    TEST_PWR_PROC_SetAndGetWattState();
    TEST_PWR_PROC_SetAndGetWattAttrs();
    TEST_PWR_PROC_AddAndDelWattProcs();
    TEST_PWR_PROC_SetAndGetSmartGridState();
    TEST_PWR_PROC_SetAndGetSmartGridProcs();
    TEST_PWR_PROC_SetAndGetSmartGridGov();
    TEST_PWR_PROC_SetWattFirstDomain();
    TEST_PWR_PROC_GetServiceState();
    TEST_PWR_PROC_SetServiceState();
    TEST_PWR_PROC_GetServiceState();
}