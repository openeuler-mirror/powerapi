/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022 All rights reserved.
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
 * Description: PowerAPI DEMO for testing the interface.
 * **************************************************************************** */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "powerapi.h"

static int g_run = 1;

static const char *GetLevelName(int level)
{
    static char debug[] = "DEBUG";
    static char info[] = "INFO";
    static char warning[] = "WARNING";
    static char error[] = "ERROR";
    switch (level) {
        case 0:
            return debug;
        case 1:
            return info;
        case 2:
            return warning;
        case 3:
            return error;
        default:
            return info;
    }
}

void LogCallback(int level, const char *fmt, va_list vl)
{
    char logLine[4096] = {0};
    char message[4000] = {0};

    if (vsnprintf(message, sizeof(message) - 1, fmt, vl) < 0) {
        return;
    }

    printf("%s: %s\n", GetLevelName(level), message);
}

static void SignalHandler()
{
    g_run = 0;
}

static void SetupSignal()
{
    // regist signal handler
    signal(SIGINT, SignalHandler);
    signal(SIGUSR1, SignalHandler);
    signal(SIGUSR2, SignalHandler);
    signal(SIGTERM, SignalHandler);
    signal(SIGKILL, SignalHandler);
}

// PWR_CPU_GetUsage
static void TEST_PWR_CPU_GetInfo()
{
    int ret;
    PWR_CPU_Info *info = (PWR_CPU_Info *)malloc(sizeof(PWR_CPU_Info));
    bzero(info, sizeof(PWR_CPU_Info));
    ret = PWR_CPU_GetInfo(info);
    printf("PWR_CPU_GetInfo ret: %d\n arch:%s\n coreNum: %d\n maxFreq:%f\n minFreq:%d\n modelName: %s\n numaNum: %d\n "
        "threadsPerCore:%d\n",
        ret, info->arch, info->coreNum, info->maxFreq, info->minFreq, info->modelName, info->numaNum,
        info->threadsPerCore);
    for (int i = 0; i < info->numaNum; i++) {
        printf("numa node %d  cpuList: %s\n", info->numa[i].nodeNo, info->numa[i].cpuList);
    }
    free(info);
}

// PWR_CPU_GetUsage
static void TEST_PWR_CPU_GetUsage()
{
    int ret;
    int buffSize = sizeof(PWR_CPU_Usage) + 128 * sizeof(PWR_CPU_CoreUsage);
    PWR_CPU_Usage *u = (PWR_CPU_Usage *)malloc(buffSize);
    bzero(u, buffSize);
    ret = PWR_CPU_GetUsage(u, buffSize);
    printf("PWR_CPU_GetUsage ret: %d, CPU avgUsage:%f, coreNum: %d \n", ret, u->avgUsage, u->coreNum);
    for (int i = 0; i < u->coreNum; i++) {
        printf("core%d usage: %f\n", u->coreUsage[i].coreNo, u->coreUsage[i].usage);
    }
    free(u);
}

// PWR_CPU_GetFreqAbility
static void TEST_PWR_CPU_GetFreqAbility()
{
    int ret = 0;
    PWR_CPU_FreqAbility freqAbi;
    bzero(&freqAbi, sizeof(PWR_CPU_FreqAbility));
    ret = PWR_CPU_GetFreqAbility(&freqAbi);
    printf("PWR_CPU_GetFreqAbility ret: %d, freqDrv:%s, govNum: %d \n", ret, freqAbi.curDriver, freqAbi.avGovNum);
    for (int i = 0; i < freqAbi.avGovNum; i++) {
        printf("index: %d, gov: %s\n", i, freqAbi.avGovList[i]);
    }
}

static void TEST_PWR_CPU_DmaSetAndGetLatency()
{
    int ret = 0;
    int la = -1;
    ret = PWR_CPU_DmaGetLatency(&la);
    printf("PWR_CPU_DmaGetLatency ret: %d, Latency:%d\n", ret, la);
    ret = PWR_CPU_DmaSetLatency(2000);
    printf("PWR_CPU_DmaSetLatency ret: %d\n", ret);
    la = -1;
    ret = PWR_CPU_DmaGetLatency(&la);
    printf("PWR_CPU_DmaGetLatency ret: %d, Latency:%d\n", ret, la);
}

static void TEST_PWR_CPU_SetAndGetFreqGov()
{
    int ret = 0;
    char gov[MAX_ELEMENT_NAME_LEN] = {0};
    ret = PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN);
    printf("PWR_CPU_GetFreqGovernor ret: %d, gov:%s\n", ret, gov);
    strncpy(gov, "ondemand", MAX_ELEMENT_NAME_LEN - 1);
    ret = PWR_CPU_SetFreqGovernor(gov);
    printf("PWR_CPU_SetFreqGovernor ret: %d\n", ret);
    bzero(gov, MAX_ELEMENT_NAME_LEN);
    ret = PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN);
    printf("PWR_CPU_GetFreqGovernor ret: %d, gov:%s\n", ret, gov);
}

int main(int argc, const char *args[])
{
    PWR_SetLogCallback(LogCallback);
    while (PWR_Register() != SUCCESS) {
        sleep(3);
        printf("main registed failed!\n");
        continue;
    }
    printf("main regist succeed.\n");

    // PWR_CPU_GetUsage
    TEST_PWR_CPU_GetUsage();

    // PWR_CPU_GetFreqAbility
    TEST_PWR_CPU_GetFreqAbility();

    // PWR_CPU_DmaSetLatency PWR_CPU_DmaGetLatency
    TEST_PWR_CPU_DmaSetAndGetLatency();

    // PWR_CPU_GetFreqGovernor
    TEST_PWR_CPU_SetAndGetFreqGov();
    // todo: 其他接口测试

    while (g_run) {
        sleep(5);
    }
    PWR_UnRegister();
    return 0;
}