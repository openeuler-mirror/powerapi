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
 * Author: queyanwen，wuhaotian
 * Create: 2022-06-23
 * Description: provide cpu service
 * **************************************************************************** */

#include "cpuservice.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "pwrdata.h"
#include "log.h"
#include "unistd.h"
#define USAGE_COLUMN 8
#define CPUS_WIDTH 6
#define LATENCY 100000
#define IDLE_COLUMN 3
#define DECIMAL 10
#define CONVERSION 1000

void UsageToLong(char *buf, unsigned long paras[])
{
    int i = 0;
    int j = 0;
    int k;
    char temp[MAX_STRING_LEN];
    while (i < USAGE_COLUMN) {
        bzero(temp, sizeof(temp));
        k = 0;
        while (buf[j] != ' ') {
            temp[k] = buf[j];
            j++;
            k++;
        }
        while (buf[j] == ' ') {
            j++;
        }
        if (i == 0) {
            i++;
        } else {
            paras[i - 1] = strtoul(temp, NULL, 0);
            i++;
        }
    }
    return;
}

void DeleteFrontChar(char str[], char a)
{
    int strLength = strlen(str);
    int point = 0;
    int front = 1;
    for (int i = 0; i < strLength; i++) {
        if ((str[i] == a) && (front == 1)) {
            continue;
        } else {
            front = 0;
            str[point] = str[i];
            point++;
        }
    }
    str[point] = '\0';
}

void DeleteChar(char str[], char a)
{
    int strLength = strlen(str);
    int point = 0;
    for (int i = 0; i < strLength; i++) {
        if ((str[i] == a)) {
            continue;
        } else {
            str[point] = str[i];
            point++;
        }
    }
    str[point] = '\0';
}

char *Match(char *str, char *want)
{
    char *a = str;
    char *b = want;
    while (*b != '\0') {
        if (*a++ != *b++) {
            return NULL;
        }
    }
    return a;
}

int DeleteSubstr(char *str, char *substr)
{
    char *a = str;
    char *next;
    while (*a != '\0') {
        next = Match(a, substr);
        if (next != NULL) {
            break;
        }
        a++;
    }
    if (*a == '\0') {
        return 0;
    }
    while (*a != '\0') {
        *a++ = *next++;
    }
    return 1;
}

int GetArch(void)
{
    PWR_CPU_Info *r = malloc(sizeof(PWR_CPU_Info));
    if (r == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return -1;
    }
    int m = CpuinfoRead(r);
    int re = -1;
    if (m != 0) {
        free(r);
        r = NULL;
        return re;
    }
    if (strstr(r->arch, "aarch64") != NULL) {
        re = 0;
    } else if (strstr(r->arch, "x86_64") != NULL) {
        re = 1;
    }
    free(r);
    r = NULL;
    return re;
}

int CpuinfoRead(PWR_CPU_Info *rstData)
{
    char cpuInfo[] =
        "lscpu|grep -E \"Architecture|Byte|Thread|On-line|CPU|Core|Model name|NUMA node\"|grep -v \"BIOS\"";
    FILE *fp = popen(cpuInfo, "r");
    if (fp == NULL) {
        return 1;
    }
    char buf[MAX_STRING_LEN];
    while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
        char *att = strtok(buf, ":");
        if (att == NULL) {
            continue;
        }
        char *value = buf + strlen(att) + 1;
        DeleteFrontChar(att, ' ');
        DeleteFrontChar(value, ' ');
        value[strlen(value) - 1] = '\0';
        if (strstr(att, "Architecture") != NULL) {
            strncpy(rstData->arch, value, strlen(value));
        } else if (strstr(att, "Model name") != NULL) {
            strncpy(rstData->modelName, value, strlen(value));
        } else if (strstr(att, "Byte Order") != NULL) {
            if (strstr(value, "Little") != NULL) {
                rstData->byteOrder = 0;
            } else {
                rstData->byteOrder = 1;
            }
        } else if ((strlen(att) == CPUS_WIDTH) && (strstr(att, "CPU(s)") != NULL)) {
            rstData->coreNum = atoi(value);
        } else if (strstr(att, "On-line CPU") != NULL) {
            strncpy(rstData->onlineList, value, strlen(value));
        } else if (strstr(att, "Thread(s) per core") != NULL) {
            rstData->threadsPerCore = atoi(value);
        } else if (strstr(att, "Core(s) per socket") != NULL) {
            rstData->coresperSocket = atoi(value);
        } else if (strstr(att, "max MHz") != NULL) {
            rstData->maxFreq = atof(value);
        } else if (strstr(att, "min MHz") != NULL) {
            rstData->minFreq = atof(value);
        } else if (strstr(att, "NUMA node(s)") != NULL) {
            rstData->numaNum = atoi(value);
        } else if (strstr(att, "NUMA node") != NULL) {
            DeleteSubstr(att, "NUMA node");
            DeleteSubstr(att, " CPU(s)");
            int j = atoi(att);
            rstData->numa[j].nodeNo = j;
            strncpy(rstData->numa[j].cpuList, value, strlen(value));
        }
    }
    pclose(fp);
    return SUCCESS;
}

int CPUUsageRead(PWR_CPU_Usage *rstData, int coreNum)
{
    FILE *fp1 = NULL;
    FILE *fp2 = NULL;
    char usage[] = "cat /proc/stat";
    unsigned long paras[2][7];
    fp1 = popen(usage, "r");
    usleep(LATENCY);
    fp2 = popen(usage, "r");
    if (fp1 == NULL || fp2 == NULL) {
        return ERR_COMMON;
    }
    char buf[MAX_STRING_LEN] = {0};
    int i = 0;
    while (i < coreNum + 1) {
        if (fgets(buf, sizeof(buf) - 1, fp1) == NULL) {
            return ERR_COMMON;
        }
        UsageToLong(buf, paras[0]);
        if (fgets(buf, sizeof(buf) - 1, fp2) == NULL) {
            return ERR_COMMON;
        }
        UsageToLong(buf, paras[1]);
        unsigned long parasSum1 = 0;
        unsigned long parasSum2 = 0;
        int j;
        for (j = 0; j < USAGE_COLUMN - 1; j++) {
            parasSum1 += paras[0][j];
            parasSum2 += paras[1][j];
        }
        if (i == 0) {
            rstData->avgUsage = 1 - ((double)(paras[1][IDLE_COLUMN] - paras[0][IDLE_COLUMN])) / (parasSum2 - parasSum1);
            rstData->coreNum = coreNum;
        } else {
            rstData->coreUsage[i - 1].coreNo = i - 1;
            rstData->coreUsage[i - 1].usage =
                1 - ((double)(paras[1][IDLE_COLUMN] - paras[0][IDLE_COLUMN])) / (parasSum2 - parasSum1);
        }
        i++;
    }
    pclose(fp1);
    pclose(fp2);
    return SUCCESS;
}

int LLCMissRead(double *lm)
{
    int m = GetArch();
    char *missStr;
    if (m == AARCH_64) {
        missStr = "perf stat -e r0033 -e instructions -a sleep 0.1 &>perf.txt";
    } else if (m == X86_64) {
        missStr = "perf stat -e LLC-load-misses -e LLC-store-misses -e instructions -a sleep 0.1 &>perf.txt";
    } else {  // Add other arch
        return 1;
    }
    FILE *fp = NULL;
    system(missStr);
    fp = fopen("perf.txt", "r");
    if (fp == NULL) {
        return 1;
    }
    char buf[MAX_STRING_LEN];
    int i = 0;
    unsigned long cacheMiss = 0;
    unsigned long ins = 0;
    while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
        if (buf == NULL) {
            return 1;
        }
        DeleteChar(buf, '\n');
        DeleteChar(buf, ' ');
        DeleteChar(buf, ',');
        if ((strstr(buf, "r0033") != NULL) || (strstr(buf, "LLC-load-misses") != NULL) ||
            (strstr(buf, "LLC-load-misses") != NULL)) {
            DeleteSubstr(buf, "r0033");
            DeleteSubstr(buf, "LLC-load-misses");
            DeleteSubstr(buf, "LLC-store-misses");
            cacheMiss += strtoul(buf, NULL, DECIMAL);
        } else if (strstr(buf, "instructions") != NULL) {
            DeleteSubstr(buf, "instructions");
            ins += strtoul(buf, NULL, DECIMAL);
        }
    }
    *lm = (double)cacheMiss / ins;
    pclose(fp);
    return 0;
}

int GetPolicys(char (*policys)[MAX_ELEMENT_NAME_LEN], int *poNum)
{
    FILE *fp = NULL;
    char policyInfo[] = "ls /sys/devices/system/cpu/cpufreq | grep policy";
    fp = popen(policyInfo, "r");
    if (fp == NULL) {
        return 1;
    }
    char buf[MAX_NAME_LEN];
    bzero(buf, sizeof(buf));
    *poNum = 0;
    while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
        DeleteChar(buf, '\n');
        strncpy(policys[*poNum], buf, strlen(buf));
        policys[*poNum][strlen(buf)] = '\0';
        (*poNum)++;
    }
    pclose(fp);
    return 0;
}

int GovernorRead(char *rstData)
{
    FILE *fp = NULL;
    char govInfo[] = "cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor";
    fp = popen(govInfo, "r");
    if (fp == NULL) {
        return 1;
    }
    char buf[MAX_STRING_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        return ERR_COMMON;
    }
    DeleteChar(buf, '\n');
    DeleteChar(buf, ' ');
    strncpy(rstData, buf, strlen(buf));
    rstData[strlen(buf)] = '\0';
    pclose(fp);
    return SUCCESS;
}

int GovernorSet(char *gov, char (*policys)[MAX_ELEMENT_NAME_LEN], int *poNum)
{
    FILE *fp = NULL;
    char *govInfo = malloc(strlen(gov) + MAX_NAME_LEN);
    if (govInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    static const char s1[] = "echo ";
    static const char s2[] = "> /sys/devices/system/cpu/cpufreq/";
    static const char s3[] = "/scaling_governor";
    int i;
    for (i = 0; i < (*poNum) - 1; i++) {
        strncpy(govInfo, s1, strlen(s1));
        govInfo[strlen(s1)] = '\0';
        strncat(govInfo, gov, strlen(gov));
        strncat(govInfo, s2, strlen(s2));
        strncat(govInfo, policys[i], strlen(policys[i]));
        strncat(govInfo, s3, strlen(s3));
        fp = popen(govInfo, "r");
        if (fp == NULL) {
            return 1;
        }
    }
    pclose(fp);
    return SUCCESS;
}

int FreqRead(PWR_CPU_CurFreq *rstData, char (*policys)[MAX_ELEMENT_NAME_LEN], int *poNum)
{
    FILE *fp = NULL;
    int m = GetArch();
    char *freqInfo = malloc(MAX_NAME_LEN);
    if (freqInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return ERR_COMMON;
    }
    static const char s1[] = "cat /sys/devices/system/cpu/cpufreq/";
    static const char s2Arm[] = "/cpuinfo_cur_freq";
    static const char s2X86[] = "/scaling_cur_freq";
    char s2[MAX_ELEMENT_NAME_LEN];
    bzero(s2, sizeof(s2));
    if (m == AARCH_64) {
        strncpy(s2, s2Arm, strlen(s2Arm));
    } else if (m == X86_64) {
        strncpy(s2, s2X86, strlen(s2X86));
    }
    char buf[MAX_STRING_LEN];
    int i;
    for (i = 0; i < (*poNum); i++) {
        strncpy(freqInfo, s1, strlen(s1));
        freqInfo[strlen(s1)] = '\0';
        strncat(freqInfo, policys[i], strlen(policys[i]));
        strncat(freqInfo, s2, strlen(s2));
        fp = popen(freqInfo, "r");
        if (fp == NULL) {
            return 1;
        }
        if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
            return ERR_COMMON;
        }
        DeleteChar(buf, '\n');
        DeleteChar(buf, ' ');
        DeleteSubstr(policys[i], "policy");
        rstData[i].policyId = atoi(policys[i]);
        rstData[i].curFreq = (double)strtoul(buf, NULL, DECIMAL) / CONVERSION;
    }
    pclose(fp);
    if (i < (*poNum)) {
        return ERR_COMMON;
    }
    return SUCCESS;
}

void GetCpuinfo(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get GetCpuInfo Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    PWR_CPU_Info *rstData = malloc(sizeof(PWR_CPU_Info));
    if (!rstData) {
        return;
    }
    bzero(rstData, sizeof(rstData));
    int rspCode = CpuinfoRead(rstData);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(PWR_CPU_Info));
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}
void GetCpuUsage(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get GetCpuUsage Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    PWR_CPU_Info *info = (PWR_CPU_Info *)malloc(sizeof(PWR_CPU_Info));
    if (info == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return;
    }
    CpuinfoRead(info);
    int coreNum = info->coreNum;
    free(info);
    PWR_CPU_Usage *rstData = malloc(sizeof(PWR_CPU_Usage) + sizeof(PWR_CPU_CoreUsage) * coreNum);
    if (!rstData) {
        return;
    }
    int rspCode = CPUUsageRead(rstData, coreNum);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(PWR_CPU_Usage) + sizeof(PWR_CPU_CoreUsage) * coreNum);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void GetLLCMiss(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get Get Cache Miss Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    double *rstData = malloc(sizeof(double));
    if (!rstData) {
        return;
    }
    int rspCode = LLCMissRead(rstData);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(double));
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void GetCpuFreqGovernor(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get Get Freq Governor Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    char *rstData = malloc(sizeof(char) * MAX_ELEMENT_NAME_LEN);
    if (!rstData) {
        return;
    }
    int rspCode = GovernorRead(rstData);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(char) * MAX_ELEMENT_NAME_LEN);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void SetCpuFreqGovernor(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Set Freq Governor Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    char policys[MAX_CPU_LIST_LEN][MAX_ELEMENT_NAME_LEN];
    bzero(policys, sizeof(policys));
    int poNum;
    GetPolicys(policys, &poNum);
    int rspCode = GovernorSet(req->data, policys, &poNum);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, NULL, 0);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void GetCpuFreq(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get Get Freq Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    char policys[MAX_CPU_LIST_LEN][MAX_ELEMENT_NAME_LEN];
    bzero(policys, sizeof(policys));
    int poNum;
    GetPolicys(policys, &poNum);
    PWR_CPU_CurFreq *rstData = malloc(sizeof(PWR_CPU_CurFreq) * poNum);
    if (!rstData) {
        return;
    }
    int rspCode = FreqRead(rstData, policys, &poNum);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(PWR_CPU_CurFreq) * poNum);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}
