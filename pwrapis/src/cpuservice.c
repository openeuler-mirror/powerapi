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
#include "log.h"
#include "unistd.h"
#include "utils.h"

const char cpuAttributes[MAX_ARRRIBUTES][MAX_NAME_LEN] = {
    "Architecture", "Model name", "Byte Order", "NUMA node(s)", "NUMA node", "CPU(s)",
    "On-line CPU", "Thread(s) per core", "Core(s) per socket", "max MHz", "min MHz"
};

int GetCpuArrId(char *att)
{
    int i;
    for (i = 0; i < MAX_ARRRIBUTES; i++) {
        if (strstr(att, cpuAttributes[i]) != NULL) {
            return i;
        }
    }
    return i;
}

int CpuInfoCopy(char *att, char *value, PWR_CPU_Info *rstData)
{
    int attId = GetCpuArrId(att);
    switch (attId) {
        case ARCH:
            StrCopy(rstData->arch, value, MAX_ELEMENT_NAME_LEN);
            break;
        case MODEL_NAME:
            StrCopy(rstData->modelName, value, MAX_NAME_LEN);
            break;
        case BYTE_OR:
            if (strstr(value, "Little") != NULL) {
                rstData->byteOrder = 0;
            } else {
                rstData->byteOrder = 1;
            }
            break;
        case NUMA_NUMBER:
            rstData->numaNum = atoi(value);
            break;
        case NUMA_NODE:
            DeleteSubstr(att, "NUMA node");
            DeleteSubstr(att, " CPU(s)");
            int j = atoi(att);
            rstData->numa[j].nodeNo = j;
            StrCopy(rstData->numa[j].cpuList, value, MAX_CPU_LIST_LEN);
            break;
        case CPU_NUMBER:
            if (strlen(att) == CPUS_WIDTH) {
                rstData->coreNum = atoi(value);
            }
            break;
        case ONLINE_CPU:
            StrCopy(rstData->onlineList, value, MAX_CPU_LIST_LEN);
            break;
        case THREADS_PER_CORE:
            rstData->threadsPerCore = atoi(value);
            break;
        case CORES_PER_SOCKET:
            rstData->coresperSocket = atoi(value);
            break;
        case MAX_MHZ:
            rstData->maxFreq = atof(value);
            break;
        case MIN_MHZ:
            rstData->minFreq = atof(value);
            break;
        default:
            break;
    }
}

int CpuInfoRead(PWR_CPU_Info *rstData)
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
        att = Ltrim(att);
        value = Ltrim(value);
        value[strlen(value) - 1] = '\0';
        CpuInfoCopy(att, value, rstData);
    }
    pclose(fp);
    return SUCCESS;
}

int GetArch(void)
{
    PWR_CPU_Info *cpuInfo = malloc(sizeof(PWR_CPU_Info));
    if (cpuInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return -1;
    }
    int m = CpuInfoRead(cpuInfo);
    int re = -1;
    if (m != 0) {
        free(cpuInfo);
        cpuInfo = NULL;
        return re;
    }
    if (strstr(cpuInfo->arch, "aarch64") != NULL) {
        re = 0;
    } else if (strstr(cpuInfo->arch, "x86_64") != NULL) {
        re = 1;
    }
    free(cpuInfo);
    cpuInfo = NULL;
    return re;
}

static int UsageToLong(char *buf, unsigned long paras[], int line)
{
    int i = 0;
    int j = 0;
    int k;
    char temp[MAX_STRING_LEN];
    while (i <= CPU_USAGE_COLUMN) {
        bzero(temp, sizeof(temp));
        k = 0;
        while (buf[j] != ' ') {
            temp[k++] = buf[j++];
        }
        while (buf[j] == ' ') {
            j++;
        }
        if (i == 0 && line > 0) {
            if (strstr(temp, "cpu") != NULL) {
                DeleteSubstr(temp, "cpu");
                paras[i] = strtoul(temp, NULL, 0);
            } else {
                return -2; // -2 means no this core usage informaton
            }
        } else if (i != 0) {
            paras[i] = strtoul(temp, NULL, 0);
        }
        i++;
    }
    if (line == 0) {
        return -1; // -1 means average cpu usage
    } else {
        return paras[0]; // return core Id
    }
}

static void CalculateUsage(PWR_CPU_Usage *rstData, unsigned long paras[2][CPU_USAGE_COLUMN], int i)
{
    unsigned long parasSum1 = 0;
    unsigned long parasSum2 = 0;
    int j;
    for (j = 1; j < CPU_USAGE_COLUMN; j++) {
        parasSum1 += paras[0][j];
        parasSum2 += paras[1][j];
    }
    if (i == 0) {
        rstData->avgUsage =
            1 - ((double)(paras[1][CPU_IDLE_COLUMN] - paras[0][CPU_IDLE_COLUMN])) / (parasSum2 - parasSum1);
    } else {
        rstData->coreUsage[paras[0][0]].coreNo = paras[0][0];
        rstData->coreUsage[paras[0][0]].usage =
            1 - ((double)(paras[1][CPU_IDLE_COLUMN] - paras[0][CPU_IDLE_COLUMN])) / (parasSum2 - parasSum1);
    }
}

int CPUUsageRead(PWR_CPU_Usage *rstData, int coreNum)
{
    const char usage[] = "cat /proc/stat";
    unsigned long paras[2][CPU_USAGE_COLUMN];
    FILE *fp1 = popen(usage, "r");
    usleep(LATENCY);
    FILE *fp2 = popen(usage, "r");
    if (fp1 == NULL || fp2 == NULL) {
        return ERR_COMMON;
    }
    char buf1[MAX_STRING_LEN] = {0};
    char buf2[MAX_STRING_LEN] = {0};
    int i = 0;
    rstData->coreNum = coreNum;
    while (i < coreNum + 1) {
        if (fgets(buf1, sizeof(buf1) - 1, fp1) == NULL) {
            return ERR_COMMON;
        }
        if (fgets(buf2, sizeof(buf2) - 1, fp2) == NULL) {
            return ERR_COMMON;
        }
        if (UsageToLong(buf1, paras[0], i) != UsageToLong(buf2, paras[1], i)) {
            return ERR_COMMON;
        }
        CalculateUsage(rstData, paras, i);
        i++;
    }
    pclose(fp1);
    pclose(fp2);
    return SUCCESS;
}

int PerfDataRead(PWR_CPU_PerfData *perfData)
{
    int m = GetArch();
    char *missStr;
    if (m == AARCH_64) {
        missStr = "perf stat -e r0033 -e instructions -e cycles -a sleep 0.1 &>perf.txt";
    } else if (m == X86_64) {
        missStr = "perf stat -e LLC-load-misses -e instructions -e cycles -a sleep 0.1 &>perf.txt";
    } else { // Add other arch
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
    unsigned long cycles = 0;
    while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
        if (buf == NULL) {
            return 1;
        }
        DeleteChar(buf, '\n');
        DeleteChar(buf, ' ');
        DeleteChar(buf, ',');
        if ((strstr(buf, "r0033") != NULL) || (strstr(buf, "LLC-load-misses") != NULL)) {
            DeleteSubstr(buf, "r0033");
            DeleteSubstr(buf, "LLC-load-misses");
            cacheMiss += strtoul(buf, NULL, DECIMAL);
        } else if (strstr(buf, "instructions") != NULL) {
            DeleteSubstr(buf, "instructions");
            ins += strtoul(buf, NULL, DECIMAL);
        } else if (strstr(buf, "cycles") != NULL) {
            DeleteSubstr(buf, "cycles");
            cycles += strtoul(buf, NULL, DECIMAL);
        }
    }
    perfData->llcMiss = (double)cacheMiss / ins;
    perfData->ipc = (double)ins / cycles;
    pclose(fp);
    return SUCCESS;
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
        StrCopy(policys[*poNum], buf, MAX_ELEMENT_NAME_LEN);
        (*poNum)++;
    }
    pclose(fp);
    return 0;
}

static int CheckGovernor(char *gov, char *policys)
{
    char *checkGovInfo = malloc(strlen(gov) + MAX_NAME_LEN);
    if (checkGovInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    const char s1[] = "cat /sys/devices/system/cpu/cpufreq/";
    const char s2[] = "/scaling_available_governors";
    StrCopy(checkGovInfo, s1, strlen(gov) + MAX_NAME_LEN);
    strncat(checkGovInfo, policys, strlen(gov));
    strncat(checkGovInfo, s2, strlen(s2));
    char buf[MAX_STRING_LEN];
    FILE *fp = popen(checkGovInfo, "r");
    if (fp == NULL || fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        return 1;
    }
    DeleteChar(buf, '\n');
    char *temp = strtok(buf, " ");
    while (temp != NULL) {
        DeleteChar(temp, ' ');
        if (strcmp(temp, gov) == 0) {
            return 0;
        }
        temp = strtok(NULL, " ");
    }
    return 1;
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
    StrCopy(rstData, buf, MAX_ELEMENT_NAME_LEN);
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
        if (CheckGovernor(gov, policys[i]) != 0) {
            return ERR_INVALIDE_PARAM;
        }
        StrCopy(govInfo, s1, strlen(gov) + MAX_NAME_LEN);
        strncat(govInfo, gov, strlen(gov));
        strncat(govInfo, s2, strlen(s2));
        strncat(govInfo, policys[i], strlen(policys[i]));
        strncat(govInfo, s3, strlen(s3));
        fp = popen(govInfo, "r");
        if (fp == NULL) {
            return ERR_COMMON;
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
        StrCopy(s2, s2Arm, MAX_ELEMENT_NAME_LEN);
    } else if (m == X86_64) {
        StrCopy(s2, s2X86, MAX_ELEMENT_NAME_LEN);
    }
    char buf[MAX_STRING_LEN];
    int i;
    for (i = 0; i < (*poNum); i++) {
        StrCopy(freqInfo, s1, MAX_NAME_LEN);
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
    int rspCode = CpuInfoRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_Info));
}
void GetCpuUsage(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get GetCpuUsage Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    int coreNum = GetCpuCoreNumber();
    PWR_CPU_Usage *rstData = malloc(sizeof(PWR_CPU_Usage) + sizeof(PWR_CPU_CoreUsage) * coreNum);
    if (!rstData) {
        return;
    }
    bzero(rstData, sizeof(sizeof(PWR_CPU_Usage) + sizeof(PWR_CPU_CoreUsage) * coreNum));
    int rspCode = CPUUsageRead(rstData, coreNum);
    printf("rspcode is %d\n", rspCode);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_Usage) + sizeof(PWR_CPU_CoreUsage) * coreNum);
}

void GetCpuPerfData(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get Get Perf Data Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    PWR_CPU_PerfData *rstData = malloc(sizeof(PWR_CPU_PerfData));
    if (!rstData) {
        return;
    }
    int rspCode = PerfDataRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_PerfData));
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
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(char) * MAX_ELEMENT_NAME_LEN);
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
    SendRspToClient(req, rspCode, NULL, 0);
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
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_CurFreq) * poNum);
}

// 总CPU核数
int GetCpuCoreNumber(void)
{
    return sysconf(_SC_NPROCESSORS_CONF);
}
