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
#include "procapitest.h"

#define MAIN_LOOP_INTERVAL 5
#define TEST_FREQ 2400
#define TEST_CORE_NUM 128
#define AVG_LEN_PER_CORE 5
#define TEST_CPU_DMA_LATENCY 2000
#define TASK_INTERVAL 1000
#define TASK_RUN_TIME 10
#define TEST_FREQ_RANGE_MIN 500
#define TEST_FREQ_RANGE_MAX 2500

static int g_run = 1;

static void PrintResult(char *function, int ret)
{
    int length = 24;
    printf("[TEST ]    ");
    printf("%-*s", length, function);
    printf(":");
    if (ret == PWR_SUCCESS) {
        printf("SUCCESS ret: %d\n", ret);
    } else {
        printf("ERROR   ret: %d\n", ret);
    }
}

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
    int length = 5;

    if (vsnprintf(message, sizeof(message) - 1, fmt, vl) < 0) {
        return;
    }

    printf("[");
    printf("%-*s", length, GetLevelName(level));
    printf("]    %s\n", message);
}

void MetaDataCallback(const PWR_COM_CallbackData *callbackData)
{
    PWR_CPU_PerfData *perfData = NULL;
    PWR_CPU_Usage *usage = NULL;
    switch (callbackData->dataType) {
        case PWR_COM_DATATYPE_CPU_PERF:
            perfData = (PWR_CPU_PerfData *)(callbackData->data);
            printf("[TASK ]    Get perf data. ipc: %f  miss: %f, ctime:%s\n", perfData->ipc, perfData->llcMiss,
                callbackData->ctime);
            break;
        case PWR_COM_DATATYPE_CPU_USAGE:
            usage = (PWR_CPU_Usage *)(callbackData->data);
            printf("[TASK ]    Get cpu usage. avgUsage: %f, coreNum:%d, ctime:%s\n", usage->avgUsage, usage->coreNum,
                callbackData->ctime);
            /* for (int i = 0; i < usage->coreNum; i++) {
                printf("      core%d usage: %f\n", usage->coreNum[i].coreNo, usage->coreNum[i].usage);
            } */
            break;
        default:
            printf("[TASK ]    Get invalide data.\n");
            break;
    }
}

void EventCallback(const PWR_COM_EventInfo *eventInfo)
{
    printf("[Event]    Get event notification\n");
    switch (eventInfo->eventType) {
        case PWR_COM_EVTTYPE_CRED_FAILED:
            printf("[Event]    ctime: %s, type: %d, info: %s\n", eventInfo->ctime,
                eventInfo->eventType, eventInfo->info);
            break;
        default:
            printf("[Event]    Get invalid event.\n");
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
/************************** COMMON ************************/
static void TEST_PWR_SetLogCallback(void)
{
    int ret = -1;
    ret = PWR_SetLogCallback(LogCallback);
    PrintResult("PWR_SetLogCallback", ret);
}

static void TEST_PWR_SetServerInfo(void)
{
    int ret = -1;
    char str[] = "/etc/sysconfig/pwrapis/pwrserver.sock";
    ret = PWR_SetServerInfo(str);
    PrintResult("PWR_SetServerInfo", ret);
}

static void TEST_PWR_Register(void)
{
    while (PWR_Register() != PWR_SUCCESS) {
        sleep(MAIN_LOOP_INTERVAL);
        PrintResult("PWR_Register", PWR_ERR_COMMON);
        continue;
    }
    PrintResult("PWR_Register", PWR_SUCCESS);
}

static void TEST_PWR_COM_DcTaskMgr(void)
{
    int ret = -1;
    ret = PWR_SetMetaDataCallback(MetaDataCallback);
    PrintResult("PWR_SetMetaDataCallback", ret);

    PWR_COM_BasicDcTaskInfo task = {0};
    task.dataType = PWR_COM_DATATYPE_CPU_PERF;
    task.interval = TASK_INTERVAL;
    ret = PWR_CreateDcTask(&task);
    PrintResult("PWR_CreateDcTask", ret);
    printf("dataType:%d\n", task.dataType);

    task.dataType = PWR_COM_DATATYPE_CPU_USAGE;
    ret = PWR_CreateDcTask(&task);
    PrintResult("PWR_CreateDcTask", ret);
    printf("dataType:%d\n", task.dataType);

    sleep(TASK_RUN_TIME);
    ret = PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_PERF);
    PrintResult("PWR_DeleteDcTask", ret);
    printf("dataType:%d\n", PWR_COM_DATATYPE_CPU_PERF);

    ret = PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_USAGE);
    PrintResult("PWR_DeleteDcTask", ret);
    printf("dataType:%d\n", PWR_COM_DATATYPE_CPU_USAGE);
}

static void TEST_PWR_SetEventCallback(void)
{
    int ret = -1;
    ret = PWR_SetEventCallback(EventCallback);
    PrintResult("PWR_SetEventCallback", ret);
}

static void TEST_PWR_RequestControlAuth(void)
{
    int ret = -1;
    ret = PWR_RequestControlAuth();
    PrintResult("PWR_RequestControlAuth", ret);
}
/************************** COMMON END************************/

/***************************** SYS ***************************/
static void TEST_SYS_SetPowerState(void)
{
    /**
     * warning: After the system sleeps, it needs to be reactivated through
     * other means (such as the IMPI interface through the BMC physical port)
    */
    int ret = -1;
    ret = PWR_SYS_SetPowerState(1);
    PrintResult("PWR_SYS_SetPowerState", ret);
    printf("PWR_SYS_SetPowerState ret: %d\n", ret);
}

static void TEST_SYS_GetCappedPower(void)
{
    int ret = -1;
    int cappedPower = -1;
    ret = PWR_SYS_GetCappedPower(&cappedPower);
    PrintResult("PWR_SYS_GetCappedPower", ret);
    printf("    Get system capped power: %d", cappedPower);
}

static void TEST_SYS_SetCappedPower(void)
{
    int ret = -1;
    int cappedPower = 450;
    ret = PWR_SYS_SetCappedPower(cappedPower);
    printf("PWR_SYS_SetCappedPower ret: %d\n", ret);
}

static void TEST_SYS_GetRtPowerInfo(void)
{
    int ret = -1;
    PWR_SYS_PowerInfo *powerInfo = (PWR_SYS_PowerInfo *)malloc(sizeof(PWR_SYS_PowerInfo));
    if (!powerInfo) {
        return;
    }
    bzero(powerInfo, sizeof(PWR_SYS_PowerInfo));
    ret = PWR_SYS_GetRtPowerInfo(powerInfo);
    PrintResult("PWR_SYS_GetRtPower", ret);
    printf("    sys rt power:%d\n", powerInfo->sysPower);
    free(powerInfo);
}

static void TEST_PWR_SYS_GetStatisticPowerInfo(void)
{
    int ret = -1;
    PWR_SYS_StatisticPowerInfo *stcPowerInfo = (PWR_SYS_StatisticPowerInfo *)malloc(
        sizeof(PWR_SYS_StatisticPowerInfo));
    if (!stcPowerInfo) {
        return;
    }
    bzero(stcPowerInfo, sizeof(PWR_SYS_StatisticPowerInfo));
    ret = PWR_SYS_GetStatisticPowerInfo(stcPowerInfo);
    PrintResult("PWR_SYS_GetStatisticPowerInfo", ret);
    printf("    Get sys statistic power info, maxSysPower: %d, avgSysPowerL: %d, totalEnergy"
        ": %lf, maxSysPowerTime: %s, startTime: %s\n", stcPowerInfo->maxSysPower,
        stcPowerInfo->avgSysPower, stcPowerInfo->totalEnergy, stcPowerInfo->maxSysPowerTime,
        stcPowerInfo->startTime);
    free(stcPowerInfo);
}
/*************************** SYS END *************************/

/***************************** CPU ***************************/
static void TEST_PWR_CPU_GetInfo(void)
{
    int ret = -1;
    PWR_CPU_Info *info = (PWR_CPU_Info *)malloc(sizeof(PWR_CPU_Info));
    if (!info) {
        return;
    }
    bzero(info, sizeof(PWR_CPU_Info));
    ret = PWR_CPU_GetInfo(info);
    PrintResult("PWR_CPU_GetInfo", ret);
    printf("    arch: %s\n    coreNum: %d\n    maxFreq: %f\n    minFreq: %f\n    "
        "modelName: %s\n    numaNum: %d\n    threadsPerCore: %d\n", info->arch,
        info->coreNum, info->maxFreq, info->minFreq, info->modelName, info->numaNum,
        info->threadsPerCore);
    for (int i = 0; i < info->numaNum; i++) {
        printf("    numa node[%d]  cpuList: %s\n", info->numa[i].nodeNo, info->numa[i].cpuList);
    }
    free(info);
}

static void TEST_PWR_CPU_GetUsage(void)
{
    int ret = -1;
    size_t buffSize = sizeof(PWR_CPU_Usage) + TEST_CORE_NUM * sizeof(PWR_CPU_CoreUsage);
    PWR_CPU_Usage *u = (PWR_CPU_Usage *)malloc(buffSize);
    if (!u) {
        return;
    }
    bzero(u, buffSize);
    ret = PWR_CPU_GetUsage(u, buffSize);
    PrintResult("PWR_CPU_GetUsage", ret);
    printf("    CPU avgUsage: %f, coreNum: %d \n", u->avgUsage, u->coreNum);
    for (int i = 0; i < u->coreNum; i++) {
        printf("    core[%d] usage: %f\n", u->coreUsage[i].coreNo, u->coreUsage[i].usage);
    }
    free(u);
}

static void TEST_PWR_CPU_GetPerfData(void)
{
    int ret = -1;
    PWR_CPU_PerfData perfData = { 0 };
    ret = PWR_CPU_GetPerfData(&perfData);
    PrintResult("PWR_CPU_GetPerfData", ret);
    printf("    IPC: %.8f, LLC misses: %.8f \n", perfData.ipc, perfData.llcMiss);
}

static void TEST_PWR_CPU_GetFreqAbility(void)
{
    int ret = -1;
    size_t len = sizeof(PWR_CPU_FreqAbility) + AVG_LEN_PER_CORE * TEST_CORE_NUM * sizeof(int);
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    if (!freqAbi) {
        return;
    }
    bzero(freqAbi, len);
    ret = PWR_CPU_GetFreqAbility(freqAbi, len);
    PrintResult("PWR_CPU_GetFreqAbility", ret);
    printf("    freqDrv: %s, govNum: %d, freqDomainNum: %d \n", freqAbi->curDriver,
        freqAbi->avGovNum, freqAbi->freqDomainNum);
    for (int i = 0; i < freqAbi->avGovNum; i++) {
        printf("    gov[%d]: %s\n", i, freqAbi->avGovList[i]);
    }
    for (int i = 0; i < freqAbi->freqDomainNum; i++) {
        char *freqDomainInfo = freqAbi->freqDomain + i * freqAbi->freqDomainStep;
        int policyId = *((int *)freqDomainInfo);
        char *affectCpuList = freqDomainInfo + sizeof(int);
        printf("    FreqDomain[%d] affectCpuList: %s\n", policyId, affectCpuList);
    }
    free(freqAbi);
}

static void TEST_PWR_CPU_GetFreqGovernor(void)
{
    int ret = -1;
    char governor[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    ret = PWR_CPU_GetFreqGovernor(governor, PWR_MAX_ELEMENT_NAME_LEN);
    PrintResult("PWR_CPU_GetFreqGovernor", ret);
    printf("    governor: %s\n", governor);
}

static void TEST_PWR_CPU_SetFreqGovernor(void)
{
    int ret = -1;
    char governor[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    char targetGov[PWR_MAX_ELEMENT_NAME_LEN] = "userspace";
    if (PWR_CPU_GetFreqGovernor(governor, PWR_MAX_ELEMENT_NAME_LEN) != 0) {
        return;
    }
    if (strcmp(governor, targetGov) == 0) {
        strcpy(targetGov, "performance");
    }

    strncpy(governor, targetGov, PWR_MAX_ELEMENT_NAME_LEN);
    ret = PWR_CPU_SetFreqGovernor(governor);
    PrintResult("PWR_CPU_SetFreqGovernor", ret);
    bzero(governor, PWR_MAX_ELEMENT_NAME_LEN);
    PWR_CPU_GetFreqGovernor(governor, PWR_MAX_ELEMENT_NAME_LEN);
    printf("    current governor: %s\n", governor);
    if (strcmp(governor, "userspace") != 0) {
        PWR_CPU_SetFreqGovernor("userspace");
    }
}

static void TEST_PWR_CPU_GetFreqRange(void)
{
    int ret = -1;
    PWR_CPU_FreqRange freqRange = {0};
    ret = PWR_CPU_GetFreqRange(&freqRange);
    PrintResult("PWR_CPU_GetFreqRange", ret);
    printf("    min freq: %d, max freq: %d\n", freqRange.minFreq, freqRange.maxFreq);
}

static void TEST_PWR_CPU_SetFreqRange(void)
{
    int ret = -1;
    PWR_CPU_FreqRange freqRange = {0};
    freqRange.minFreq = TEST_FREQ_RANGE_MIN;
    freqRange.maxFreq = TEST_FREQ_RANGE_MAX;
    ret = PWR_CPU_SetFreqRange(&freqRange);
    PrintResult("PWR_CPU_SetFreqRange", ret);
    bzero(&freqRange, sizeof(PWR_CPU_FreqRange));
    PWR_CPU_GetFreqRange(&freqRange);
    printf("    current min freq: %d, max freq: %d\n", freqRange.minFreq, freqRange.maxFreq);
}

static void TEST_PWR_CPU_GetFreq(void)
{
    int ret = -1;
    int num = 0;
    int spec = 0;
    int i = 0;

    /**
     * Test 1: spec = 0, get all policy freq.
     * Set the num to the number of CPU cores
     * (it is possible that one kernel corresponds to one policy)
     */
    num = TEST_CORE_NUM;
    spec = 0;
    PWR_CPU_CurFreq cpuCurFreq1[num];
    bzero(cpuCurFreq1, num * sizeof(PWR_CPU_CurFreq));
    ret = PWR_CPU_GetFreq(cpuCurFreq1, &num, spec);
    PrintResult("1  PWR_CPU_GetFreq", ret);
    for (i = 0; i < num; i++) {
        printf("    policy[%d]: %lf\n", cpuCurFreq1[i].policyId, cpuCurFreq1[i].curFreq);
    }

    /**
     * Test 2: spec = 0 num = 2. get the previous 2 policies' freq
     */
    ret = -1;
    // 2: previous 2 policies
    num = 2;
    spec = 0;
    PWR_CPU_CurFreq cpuCurFreq2[num];
    bzero(cpuCurFreq2, num * sizeof(PWR_CPU_CurFreq));
    ret = PWR_CPU_GetFreq(cpuCurFreq2, &num, spec);
    PrintResult("2  PWR_CPU_GetFreq", ret);
    for (i = 0; i < num; i++) {
        printf("    policy[%d]: %lf\n", cpuCurFreq2[i].policyId, cpuCurFreq2[i].curFreq);
    }

    /**
     * Test 3: spec = 1, get the two target policy freq
     */
    ret = -1;
    // 2: previous 2 policies
    num = 2;
    spec = 1;
    PWR_CPU_CurFreq cpuCurFreq3[num];
    bzero(cpuCurFreq3, num * sizeof(PWR_CPU_CurFreq));
    cpuCurFreq3[0].policyId = 0;
    // 32 : the Id of the second policy.
    cpuCurFreq3[1].policyId = 32;
    ret = PWR_CPU_GetFreq(cpuCurFreq3, &num, spec);
    PrintResult("3  PWR_CPU_GetFreq", ret);
    for (i = 0; i < num; i++) {
        printf("    policy[%d]: %lf\n", cpuCurFreq3[i].policyId, cpuCurFreq3[i].curFreq);
    }
}

static void TEST_PWR_CPU_SetFreq(void)
{
    int ret = -1;
    int num = 1;
    PWR_CPU_CurFreq cpuCurFreq[num];
    bzero(cpuCurFreq, num * sizeof(PWR_CPU_CurFreq));
    cpuCurFreq[0].policyId = 0;
    cpuCurFreq[0].curFreq = TEST_FREQ;
    ret = PWR_CPU_SetFreq(cpuCurFreq, num);
    PrintResult("PWR_CPU_SetFreq", ret);

    int spec = 1;
    bzero(cpuCurFreq, num * sizeof(PWR_CPU_CurFreq));
    cpuCurFreq[0].policyId = 0;
    ret = PWR_CPU_GetFreq(cpuCurFreq, &num, spec);
    printf("    current policy[%d]: %lf\n", cpuCurFreq[0].policyId, cpuCurFreq[0].curFreq);
}

static void TEST_PWR_CPU_GovAttrs(void)
{
    int ret = 0;
    char gov[] = "ondemand";
    char sr[] = "sampling_rate";
    char srValue[] = "9000";
    PWR_CPU_SetFreqGovernor(gov);
    PWR_CPU_FreqGovAttrs attrs = {0};
    ret = PWR_CPU_GetFreqGovAttrs(&attrs);
    PrintResult("1 PWR_CPU_GetFreqGovAttrs", ret);
    for (int i = 0; i < attrs.attrNum; i++) {
        printf("attr%d: %s: %s\n", i, attrs.attrs[i].key, attrs.attrs[i].value);
    }

    PWR_CPU_FreqGovAttr attr = {0};
    strncpy(attr.gov, gov, strlen(gov));
    strncpy(attr.attr.key, sr, strlen(sr));
    ret = PWR_CPU_GetFreqGovAttr(&attr);
    PrintResult("2 PWR_CPU_GetFreqGovAttr", ret);
    printf("attr: %s: %s: %s\n", gov, sr, attr.attr.value);

    strncpy(attr.attr.value, srValue, PWR_MAX_VALUE_LEN);
    ret = PWR_CPU_SetFreqGovAttr(&attr);
    PrintResult("3 PWR_CPU_SetFreqGovAttr", ret);
}

static void TEST_PWR_CPU_DmaSetAndGetLatency(void)
{
    int ret = 0;
    int la = -1;
    ret = PWR_CPU_DmaGetLatency(&la);
    PrintResult("PWR_CPU_DmaGetLatency", ret);
    printf("latency: %d\n", la);
    ret = PWR_CPU_DmaSetLatency(TEST_CPU_DMA_LATENCY);
    PrintResult("PWR_CPU_DmaSetLatency", ret);
    la = -1;
    ret = PWR_CPU_DmaGetLatency(&la);
    PrintResult("PWR_CPU_DmaGetLatency", ret);
    printf("latency: %d\n", la);
}
/*************************** CPU END *************************/

/***************************** DISK **************************/
static void TEST_PWR_DISK_GetList(void)
{
    int ret = -1;
    int len = 10;
    char diskList[len][PWR_MAX_ELEMENT_NAME_LEN];
    memset(diskList, 0, sizeof(diskList));
    ret = PWR_DISK_GetList(diskList, &len);
    PrintResult("PWR_DISK_GetList", ret);
    for (int i = 0; i < len; i++) {
        printf("    disk[%d]: %s\n", i, diskList[i]);
    }
}
/*************************** DISK END ************************/

int main(int argc, const char *args[])
{
    /********** Common **********/
    TEST_PWR_SetServerInfo();
    TEST_PWR_SetLogCallback();
    TEST_PWR_SetEventCallback();
    TEST_PWR_Register();
    TEST_PWR_RequestControlAuth();

    /************ Sys ***********/
    // TEST_SYS_SetPowerState();
    // TEST_SYS_GetCappedPower();
    // TEST_SYS_SetCappedPower();
    TEST_SYS_GetRtPowerInfo();
    // TEST_PWR_SYS_GetStatisticPowerInfo();

    /************ CPU ***********/
    TEST_PWR_CPU_GetInfo();
    TEST_PWR_CPU_GetUsage();
    TEST_PWR_CPU_GetPerfData();
    TEST_PWR_CPU_GetFreqAbility();
    TEST_PWR_CPU_GetFreqGovernor();
    TEST_PWR_CPU_SetFreqGovernor();
    TEST_PWR_CPU_GetFreqRange();
    TEST_PWR_CPU_SetFreqRange();
    TEST_PWR_CPU_GetFreq();
    TEST_PWR_CPU_SetFreq();
    TEST_PWR_CPU_GovAttrs();
    // TEST_PWR_CPU_DmaSetAndGetLatency();

    /************ DISK ***********/
    // TEST_PWR_DISK_GetList();

    // TEST_PWR_COM_DcTaskMgr();
    /************ PROC ***********/
    TEST_PROC_AllFunc();
    // todo: 其他接口测试
    while (g_run) {
        sleep(MAIN_LOOP_INTERVAL);
    }
    PWR_ReleaseControlAuth();
    PWR_UnRegister();
    return 0;
}