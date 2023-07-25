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
 * Description: PowerAPI DEMO for testing the interface.
 * **************************************************************************** */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "powerapi.h"

#define MAIN_LOOP_INTERVAL 5
#define TEST_FREQ 2400
#define TEST_CORE_NUM 128
#define AVG_LEN_PER_CORE 5
#define TEST_CPU_DMA_LATENCY 2000
#define TASK_INTERVAL 1000
#define TASK_RUN_TIME 10
#define TEST_FREQ_RANGE_MIN 1100
#define TEST_FREQ_RANGE_MAX 2500

static int g_run = 1;

enum {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR
};

static const char *GetLevelName(int level)
{
    static char debug[] = "DEBUG";
    static char info[] = "INFO";
    static char warning[] = "WARNING";
    static char error[] = "ERROR";
    switch (level) {
        case DEBUG:
            return debug;
        case INFO:
            return info;
        case WARNING:
            return warning;
        case ERROR:
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

void MetaDataCallback(const PWR_COM_CallbackData *callbackData)
{
    PWR_CPU_PerfData *perfData = NULL;
    PWR_CPU_Usage *usage = NULL;
    switch (callbackData->dataType) {
        case PWR_COM_DATATYPE_CPU_PERF:
            perfData = (PWR_CPU_PerfData *)(callbackData->data);
            printf("[TASK]Get PERF data. ipc: %f  miss: %f, ctime:%s\n", perfData->ipc, perfData->llcMiss,
                callbackData->ctime);
            break;
        case PWR_COM_DATATYPE_CPU_USAGE:
            usage = (PWR_CPU_Usage *)(callbackData->data);
            printf("[TASK]Get Cpu Usage. avgUsage: %f, coreNum:%d, ctime:%s\n", usage->avgUsage, usage->coreNum,
                callbackData->ctime);
            /* for (int i = 0; i < usage->coreNum; i++) {
                printf("      core%d usage: %f\n", usage->coreNum[i].coreNo, usage->coreNum[i].usage);
            } */
            break;
        default:
            printf("[TASK]Get INVALIDE data.\n");
            break;
    }
}

static void SignalHandler(int none)
{
    g_run = 0;
}

static void SetupSignal(void)
{
    // regist signal handler
    (void)signal(SIGINT, SignalHandler);
    (void)signal(SIGUSR1, SignalHandler);
    (void)signal(SIGUSR2, SignalHandler);
    (void)signal(SIGTERM, SignalHandler);
    (void)signal(SIGKILL, SignalHandler);
}

static void TEST_SYS_SetPowerState(void)
{
    int ret = 0;
    ret = PWR_SYS_SetPowerState(1);
    printf("PWR_SYS_SetPowerState ret: %d\n", ret);
}

static void TEST_SYS_GetRtPowerInfo(void)
{
    int ret;
    PWR_SYS_PowerInfo *u = (PWR_SYS_PowerInfo *)malloc(sizeof(PWR_SYS_PowerInfo));
    if (!u) {
        return;
    }
    bzero(u, sizeof(PWR_SYS_PowerInfo));
    ret = PWR_SYS_GetRtPowerInfo(u);
    printf("PWR_SYS_GetRtPower ret: %d, SYS power:%f\n", ret, u->sysPower);
    free(u);
}

// PWR_CPU_GetUsage
static void TEST_PWR_CPU_GetInfo(void)
{
    int ret;
    PWR_CPU_Info *info = (PWR_CPU_Info *)malloc(sizeof(PWR_CPU_Info));
    if (!info) {
        return;
    }
    bzero(info, sizeof(PWR_CPU_Info));
    ret = PWR_CPU_GetInfo(info);
    printf("PWR_CPU_GetInfo ret: %d\n arch:%s\n coreNum: %d\n maxFreq:%f\n minFreq:%f\n modelName: %s\n numaNum: %d\n "
        "threadsPerCore:%d\n",
        ret, info->arch, info->coreNum, info->maxFreq, info->minFreq, info->modelName, info->numaNum,
        info->threadsPerCore);
    for (int i = 0; i < info->numaNum; i++) {
        printf("numa node %d  cpuList: %s\n", info->numa[i].nodeNo, info->numa[i].cpuList);
    }
    free(info);
}

// PWR_CPU_GetUsage
static void TEST_PWR_CPU_GetUsage(void)
{
    int ret;
    size_t buffSize = sizeof(PWR_CPU_Usage) + TEST_CORE_NUM * sizeof(PWR_CPU_CoreUsage);
    PWR_CPU_Usage *u = (PWR_CPU_Usage *)malloc(buffSize);
    if (!u) {
        return;
    }
    bzero(u, buffSize);
    ret = PWR_CPU_GetUsage(u, buffSize);
    printf("PWR_CPU_GetUsage ret: %d, CPU avgUsage:%f, coreNum: %d \n", ret, u->avgUsage, u->coreNum);
    for (int i = 0; i < u->coreNum; i++) {
        printf("core%d usage: %f\n", u->coreUsage[i].coreNo, u->coreUsage[i].usage);
    }
    free(u);
}

// PWR_CPU_GetPerfData
static void TEST_PWR_CPU_GetPerfData(void)
{
    int ret;
    PWR_CPU_PerfData perfData = { 0 };
    ret = PWR_CPU_GetPerfData(&perfData);
    printf("PWR_CPU_GetPerfData ret: %d, IPC: %.8f  LLC misses: %.8f \n", ret, perfData.ipc, perfData.llcMiss);
}

// PWR_CPU_GetFreqAbility
static void TEST_PWR_CPU_GetFreqAbility(void)
{
    int ret = 0;
    size_t len = sizeof(PWR_CPU_FreqAbility) + AVG_LEN_PER_CORE * TEST_CORE_NUM * sizeof(int);
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    if (!freqAbi) {
        return;
    }
    bzero(freqAbi, len);
    ret = PWR_CPU_GetFreqAbility(freqAbi, len);
    printf("PWR_CPU_GetFreqAbility ret: %d, freqDrv:%s, govNum: %d, freqDomainNum:%d \n", ret, freqAbi->curDriver,
        freqAbi->avGovNum, freqAbi->freqDomainNum);
    for (int i = 0; i < freqAbi->avGovNum; i++) {
        printf("gov index: %d, gov: %s\n", i, freqAbi->avGovList[i]);
    }
    for (int i = 0; i < freqAbi->freqDomainNum; i++) {
        char *freqDomainInfo = freqAbi->freqDomain + i * freqAbi->freqDomainStep;
        int policyId = *((int *)freqDomainInfo);
        char *affectCpuList = freqDomainInfo + sizeof(int);
        printf("FreqDomain %d, affectCpuList：%s\n", policyId, affectCpuList);
    }
    free(freqAbi);
}

static void TEST_PWR_CPU_GetAndSetFreqRange(void)
{
    int ret = 0;
    size_t len = sizeof(PWR_CPU_FreqRange);
    PWR_CPU_FreqRange *freqRange = (PWR_CPU_FreqRange *)malloc(len);
    if (!freqRange) {
        return;
    }
    bzero(freqRange, len);
    ret = PWR_CPU_GetFreqRange(freqRange);
    printf("PWR_CPU_GetFreqRange ret: %d, MinFreq:%d, MaxFreq: %d\n", ret, freqRange->minFreq, freqRange->maxFreq);
    freqRange->minFreq = TEST_FREQ_RANGE_MIN;
    freqRange->maxFreq = TEST_FREQ_RANGE_MAX;
    ret = PWR_CPU_SetFreqRange(freqRange);
    printf("PWR_CPU_SetFreqRange ret: %d\n", ret);
    ret = PWR_CPU_GetFreqRange(freqRange);
    printf("PWR_CPU_GetFreqRange ret: %d, MinFreq:%d, MaxFreq: %d\n", ret, freqRange->minFreq, freqRange->maxFreq);
    free(freqRange);
}

static void TEST_PWR_CPU_SetAndGetFreqGov(void)
{
    int ret = 0;
    char gov[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    ret = PWR_CPU_GetFreqGovernor(gov, PWR_MAX_ELEMENT_NAME_LEN);
    printf("PWR_CPU_GetFreqGovernor ret: %d, gov:%s\n", ret, gov);
    strncpy(gov, "userspace", PWR_MAX_ELEMENT_NAME_LEN - 1);
    ret = PWR_CPU_SetFreqGovernor(gov);
    printf("PWR_CPU_SetFreqGovernor ret: %d\n", ret);
    bzero(gov, PWR_MAX_ELEMENT_NAME_LEN);
    ret = PWR_CPU_GetFreqGovernor(gov, PWR_MAX_ELEMENT_NAME_LEN);
    printf("PWR_CPU_GetFreqGovernor ret: %d, gov:%s\n", ret, gov);
}

// PWR_CPU_GetFreq PWR_CPU_SetFreq

static void TEST_PWR_CPU_SetAndGetCurFreq(void)
{
    int ret = 0;
    uint32_t len = TEST_CORE_NUM;
    PWR_CPU_CurFreq curFreq[len];
    bzero(curFreq, len * sizeof(PWR_CPU_CurFreq));
    int spec = 0;
    ret = PWR_CPU_GetFreq(curFreq, &len, spec);
    printf("PWR_CPU_GetFreq ret: %d, len:%d\n", ret, len);
    for (int i = 0; i < len; i++) {
        printf("Freq Policy %d curFreq:%lf\n", curFreq[i].policyId, curFreq[i].curFreq);
    }
    len = TEST_CORE_NUM;
    bzero(curFreq, len * sizeof(PWR_CPU_CurFreq));
    curFreq[0].policyId = 0;
    curFreq[0].curFreq = TEST_FREQ;
    ret = PWR_CPU_SetFreq(curFreq, 1);
    printf("PWR_CPU_SetFreq ret: %d\n", ret);
    len = 1;
    spec = 1;
    curFreq[0].curFreq = 0;
    ret = PWR_CPU_GetFreq(curFreq, &len, spec);
    printf("Freq Policy %d curFreq:%lf\n", curFreq[0].policyId, curFreq[0].curFreq);
}

static void TEST_PWR_CPU_DmaSetAndGetLatency(void)
{
    int ret = 0;
    int la = -1;
    ret = PWR_CPU_DmaGetLatency(&la);
    printf("PWR_CPU_DmaGetLatency ret: %d, Latency:%d\n", ret, la);
    ret = PWR_CPU_DmaSetLatency(TEST_CPU_DMA_LATENCY);
    printf("PWR_CPU_DmaSetLatency ret: %d\n", ret);
    la = -1;
    ret = PWR_CPU_DmaGetLatency(&la);
    printf("PWR_CPU_DmaGetLatency ret: %d, Latency:%d\n", ret, la);
}


static void TEST_PWR_COM_DcTaskMgr(void)
{
    int ret = PWR_SUCCESS;
    ret = PWR_SetMetaDataCallback(MetaDataCallback);
    printf("PWR_SetMetaDataCallback ret: %d\n", ret);

    PWR_COM_BasicDcTaskInfo task = { 0 };
    task.dataType = PWR_COM_DATATYPE_CPU_PERF;
    task.interval = TASK_INTERVAL;
    ret = PWR_CreateDcTask(&task);
    printf("PWR_CreateDcTask. dataType:%d ret: %d\n", task.dataType, ret);
    task.dataType = PWR_COM_DATATYPE_CPU_USAGE;
    ret = PWR_CreateDcTask(&task);
    printf("PWR_CreateDcTask. dataType:%d ret: %d\n", task.dataType, ret);

    sleep(TASK_RUN_TIME);
    ret = PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_PERF);
    printf("PWR_DeleteDcTask. dataType:%d ret: %d\n", PWR_COM_DATATYPE_CPU_PERF, ret);
    ret = PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_USAGE);
    printf("PWR_DeleteDcTask. dataType:%d ret: %d\n", PWR_COM_DATATYPE_CPU_USAGE, ret);
}

static void TEST_PWR_SetServerInfo(void)
{
    char str[] = "/etc/sysconfig/pwrapis/pwrserver.sock";
    if (PWR_SetServerInfo(str) != PWR_SUCCESS) {
        printf("PWR_SetServerInfo. failed");
    }
    printf("success");
}

void EventCallback(const PWR_COM_EventInfo *eventInfo)
{
    printf("[Event] Get event notification\n");
    switch (eventInfo->eventType) {
        case PWR_COM_EVTTYPE_CRED_FAILED:
            printf("[Event] ctime:%s, type:%d\n", eventInfo->ctime, eventInfo->eventType);
            printf("[Event] info:%s\n", eventInfo->info);
            break;
        default:
            printf("[Event] Get invalid event.\n");
            break;
    }
}

int main(int argc, const char *args[])
{
    TEST_PWR_SetServerInfo();
    PWR_SetLogCallback(LogCallback);
    PWR_SetEventCallback(EventCallback);
    while (PWR_Register() != PWR_SUCCESS) {
        sleep(MAIN_LOOP_INTERVAL);
        printf("main registed failed!\n");
        continue;
    }
    printf("main regist succeed.\n");
    int ret = PWR_RequestControlAuth();
    if (ret != PWR_SUCCESS) {
        printf("Request Control Auth failed.\n");
    } else {
        printf("Request Control Auth succeed.\n");
    }

    TEST_PWR_CPU_GetInfo();
    // PWR_CPU_GetUsage
    TEST_PWR_CPU_GetUsage();

    // PWR_CPU_GetUsage
    TEST_PWR_CPU_GetPerfData();

    // PWR_CPU_GetFreqAbility
    TEST_PWR_CPU_GetFreqAbility();

    // PWR_CPU_GetFreqGovernor PWR_CPU_SetFreqGovernor
    // TEST_PWR_CPU_SetAndGetFreqGov();

    TEST_SYS_GetRtPowerInfo();
    // TEST_SYS_SetPowerState();
    // PWR_CPU_GetCurFreq PWR_CPU_SetCurFreq
    TEST_PWR_CPU_SetAndGetCurFreq();

    TEST_PWR_CPU_GetAndSetFreqRange();

    // PWR_CPU_DmaSetLatency PWR_CPU_DmaGetLatency
    // TEST_PWR_CPU_DmaSetAndGetLatency();
    // TEST_PWR_COM_DcTaskMgr();
    // todo: 其他接口测试
    while (g_run) {
        sleep(MAIN_LOOP_INTERVAL);
    }
    PWR_ReleaseControlAuth();
    PWR_UnRegister();
    return 0;
}