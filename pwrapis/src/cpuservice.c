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

#include "fcntl.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "cpuservice.h"

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

static void FreqSortByPolicy(PWR_CPU_CurFreq *rstData, int len)
{
    int i, j;
    PWR_CPU_CurFreq temp;
    for (i = 0; i < len; i++) {
        for (j = 0; j < len - i - 1; j++) {
            if (rstData[j].policyId > rstData[j + 1].policyId) {
                temp = rstData[j + 1];
                rstData[j + 1] = rstData[j];
                rstData[j] = temp;
            }
        }
    }
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
        return re;
    }
    if (strstr(cpuInfo->arch, "aarch64") != NULL) {
        re = 0;
    } else if (strstr(cpuInfo->arch, "x86_64") != NULL) {
        re = 1;
    }
    free(cpuInfo);
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
    if (fp1 == NULL) {
        return ERR_COMMON;
    }
    usleep(LATENCY);
    FILE *fp2 = popen(usage, "r");
    if (fp2 == NULL) {
        pclose(fp1);
        return ERR_COMMON;
    }
    char buf1[MAX_STRING_LEN] = {0};
    char buf2[MAX_STRING_LEN] = {0};
    int i = 0;
    rstData->coreNum = coreNum;
    while (i < coreNum + 1) {
        if (fgets(buf1, sizeof(buf1) - 1, fp1) == NULL) {
            pclose(fp1);
            pclose(fp2);
            return ERR_COMMON;
        }
        if (fgets(buf2, sizeof(buf2) - 1, fp2) == NULL) {
            pclose(fp1);
            pclose(fp2);
            return ERR_COMMON;
        }
        if (UsageToLong(buf1, paras[0], i) != UsageToLong(buf2, paras[1], i)) {
            pclose(fp1);
            pclose(fp2);
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
            pclose(fp);
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

static void MergeDuplicatePolicys(PWR_CPU_CurFreq *target, int *len)
{
    int length = *len;
    int cpuNum = sysconf(_SC_NPROCESSORS_CONF);
    int *validId = (int *)malloc(cpuNum * sizeof(int));
    if (validId == NULL) {
        return;
    }
    memset(validId, 0, sizeof(int) * cpuNum);
    for (int i = 0; i < length; i++) {
        if (target[i].policyId < cpuNum) {
            validId[target[i].policyId] = 1;
        }
    }
    int count = 0;
    for (int i = 0; i < cpuNum; i++) {
        if (validId[i] == 1) {
            target[count].policyId = i;
            count++;
        }
    }
    *len = count;
    free(validId);
}

static int CheckPolicys(PWR_CPU_CurFreq *target, int len)
{
    char policys[MAX_CPU_LIST_LEN][MAX_ELEMENT_NAME_LEN];
    bzero(policys, sizeof(policys));
    int poNum, i;
    if (GetPolicys(policys, &poNum) == 0) {
        int policysId[poNum];
        // convert policys to int
        for (i = 0; i < poNum; i++) {
            DeleteSubstr(policys[i], "policy");
            policysId[i] = atoi(policys[i]);
        }
        // Determine whether the policyId is valid.
        for (i = 0; i < len; i++) {
            if (InIntRange(policysId, poNum, target[i].policyId) == 1) {
                return ERR_INVALIDE_PARAM;
            }
        }
        return 0;
    }
    return 1;
}

static int InputTargetPolicys(PWR_CPU_CurFreq *target, char (*policys)[MAX_ELEMENT_NAME_LEN], int poNum)
{
    char buffer[MAX_ELEMENT_NAME_LEN] = {0};
    for (int i = 0; i < poNum; i++) {
        StrCopy(policys[i], "policy", MAX_ELEMENT_NAME_LEN);
        if (snprintf(buffer, MAX_ELEMENT_NAME_LEN - 1, "%d", target->policyId) < 0) {
            return 1;
        }
        strncat(policys[i], buffer, strlen(buffer));
    }
    return 0;
}

static int AllGovernorsRead(char (*govList)[MAX_ELEMENT_NAME_LEN], int *govNum)
{
    char buf[MAX_ELEMENT_NAME_LEN * MAX_GOV_NUM] = {0};
    const char govInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_available_governors";
    int fd = open(govInfo, O_RDONLY);
    if (fd == -1) {
        return 1;
    }
    if (read(fd, buf, MAX_ELEMENT_NAME_LEN * MAX_GOV_NUM - 1) <= 0) {
        close(fd);
        return 1;
    }
    close(fd);
    DeleteChar(buf, '\n');
    char *temp = strtok(buf, " ");
    *govNum = 0;
    while (temp != NULL) {
        DeleteChar(temp, ' ');
        StrCopy(govList[(*govNum)++], temp, MAX_ELEMENT_NAME_LEN);
        temp = strtok(NULL, " ");
    }
    return 0;
}

static int CheckAvailableGovernor(char *gov, char *policys)
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
    if (fp == NULL) {
        free(checkGovInfo);
        return 1;
    }
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        free(checkGovInfo);
        pclose(fp);
        return 1;
    }
    DeleteChar(buf, '\n');
    char *temp = strtok(buf, " ");
    while (temp != NULL) {
        DeleteChar(temp, ' ');
        if (strcmp(temp, gov) == 0) {
            free(checkGovInfo);
            pclose(fp);
            return 0;
        }
        temp = strtok(NULL, " ");
    }
    pclose(fp);
    return 1;
}

int CurrentGovernorRead(char *rstData)
{
    FILE *fp = NULL;
    char govInfo[] = "cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor";
    fp = popen(govInfo, "r");
    if (fp == NULL) {
        return 1;
    }
    char buf[MAX_STRING_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        pclose(fp);
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
    int i;
    for (i = 0; i < (*poNum); i++) {
        if (CheckAvailableGovernor(gov, policys[i]) != 0) {
            return ERR_INVALIDE_PARAM;
        }
    }
    char *govInfo = malloc(strlen(gov) + MAX_NAME_LEN);
    if (govInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    static const char s1[] = "echo ";
    static const char s2[] = "> /sys/devices/system/cpu/cpufreq/";
    static const char s3[] = "/scaling_governor";
    for (i = 0; i < (*poNum); i++) {
        StrCopy(govInfo, s1, strlen(gov) + MAX_NAME_LEN);
        strncat(govInfo, gov, strlen(gov));
        strncat(govInfo, s2, strlen(s2));
        strncat(govInfo, policys[i], strlen(policys[i]));
        strncat(govInfo, s3, strlen(s3));
        FILE *fp = popen(govInfo, "r");
        if (fp == NULL) {
            free(govInfo);
            return ERR_COMMON;
        }
        pclose(fp);
        // todo: write back precious governor
    }
    return SUCCESS;
}

static int FreqRead(PWR_CPU_CurFreq *rstData, char (*policys)[MAX_ELEMENT_NAME_LEN], int *poNum)
{
    int m = GetArch();
    char freqInfo[MAX_NAME_LEN] = {0};
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
        FILE *fp = popen(freqInfo, "r");
        if (fp == NULL) {
            return 1;
        }
        if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
            pclose(fp);
            return ERR_COMMON;
        }
        DeleteChar(buf, '\n');
        DeleteChar(buf, ' ');
        DeleteSubstr(policys[i], "policy");
        pclose(fp);
        rstData[i].policyId = atoi(policys[i]);
        rstData[i].curFreq = (double)strtoul(buf, NULL, DECIMAL) / CONVERSION;
    }
    FreqSortByPolicy(rstData, (*poNum));
    return SUCCESS;
}

static int FreqSet(PWR_CPU_CurFreq *target, int len)
{
    char setFreqInfo[MAX_NAME_LEN] = {0};
    static const char s1[] = "echo ";
    static const char s2[] = " > /sys/devices/system/cpu/cpufreq/policy";
    static const char s3[] = "/scaling_setspeed";
    int i, freq;
    char buffer[MAX_ELEMENT_NAME_LEN] = {0};
    for (i = 0; i < len; i++) {
        StrCopy(setFreqInfo, s1, MAX_NAME_LEN);
        freq = (int)target[i].curFreq * THOUSAND;
        if (snprintf(buffer, MAX_ELEMENT_NAME_LEN - 1, "%d", freq) < 0) {
            return ERR_COMMON;
        }
        strncat(setFreqInfo, buffer, strlen(buffer));
        strncat(setFreqInfo, s2, strlen(s2));
        if (snprintf(buffer, MAX_ELEMENT_NAME_LEN - 1, "%d", target[i].policyId) < 0) {
            return ERR_COMMON;
        }
        strncat(setFreqInfo, buffer, strlen(buffer));
        strncat(setFreqInfo, s3, strlen(s3));
        FILE *fp = popen(setFreqInfo, "r");
        if (fp == NULL) {
            return ERR_COMMON;
        }
        pclose(fp);
    }
    return SUCCESS;
}

static int FreqDriverRead(char *buf, int bufLen)
{
    const char driverInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_driver";
    int fd = open(driverInfo, O_RDONLY);
    if (fd == -1) {
        return 1;
    }
    if (read(fd, buf, bufLen - 1) <= 0) {
        close(fd);
        return 1;
    }
    close(fd);
    DeleteChar(buf, '\n');
    buf[strlen(buf)] = '\0';
    return 0;
}

static int FreqDomainRead(char *buf, char (*policys)[MAX_ELEMENT_NAME_LEN], int domainNum, int step)
{
    char domainInfo[MAX_NAME_LEN] = {0};
    char domainbuf[MAX_CPU_LIST_LEN] = {0};
    char temp[MAX_ELEMENT_NAME_LEN] = {0};
    char s1[] = "/sys/devices/system/cpu/cpufreq/";
    char s2[] = "/affected_cpus";
    int i;
    for (i = 0; i < domainNum; i++) {
        StrCopy(domainInfo, s1, MAX_NAME_LEN);
        strncat(domainInfo, policys[i], strlen(policys[i]));
        strncat(domainInfo, s2, strlen(s2));
        int fd = open(domainInfo, O_RDONLY);
        if (fd == -1) {
            close(fd);
            return 1;
        }
        if (read(fd, domainbuf, MAX_CPU_LIST_LEN - 1) <= 0) {
            close(fd);
            return 1;
        }
        close(fd);
        DeleteChar(domainbuf, '\n');
        // convert policys to int
        StrCopy(temp, policys[i], MAX_ELEMENT_NAME_LEN);
        DeleteSubstr(temp, "policy");
        buf[i * step] = atoi(temp);
        StrCopy(buf + i * step + sizeof(int), domainbuf, step - sizeof(int));
    }
    return 0;
}


static int FreqAbilityRead(PWR_CPU_FreqAbility *rstData, char (*policys)[MAX_ELEMENT_NAME_LEN])
{
    if (FreqDriverRead(rstData->curDriver, MAX_ELEMENT_NAME_LEN) != SUCCESS) {
        return ERR_COMMON;
    }
    if (AllGovernorsRead(rstData->avGovList, &(rstData->avGovNum)) != SUCCESS) {
        return ERR_COMMON;
    }
    if (FreqDomainRead(rstData->freqDomain, policys, rstData->freqDomainNum, rstData->freqDomainStep) != SUCCESS) {
        return ERR_COMMON;
    }
}

static int CheckFreqInRange(PWR_CPU_CurFreq *target, int len, PWR_CPU_FreqRange freqRange)
{
    for (int i = 0; i < len; i++) {
        if (target[i].curFreq < freqRange.minFreq || target[i].curFreq > freqRange.maxFreq) {
            return 1;
        }
    }
    return 0;
}

static int FreqRangeRead(PWR_CPU_FreqRange *rstData)
{
    char buf[MAX_ELEMENT_NAME_LEN] = {0};
    const char minFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq";
    const char maxFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq";
    if (ReadFile(minFreqInfo, buf, MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    rstData->minFreq = atoi(buf) / THOUSAND;
    if (ReadFile(maxFreqInfo, buf, MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    rstData->maxFreq = atoi(buf) / THOUSAND;
    return 0;
}

static int FreqRangeSet(PWR_CPU_FreqRange *rstData)
{
    char policys[MAX_CPU_LIST_LEN][MAX_ELEMENT_NAME_LEN] = {0};
    int poNum, i;
    if (GetPolicys(policys, &poNum) != 0) {
        return 1;
    }
    char buf[MAX_ELEMENT_NAME_LEN] = {0};

    // set min freq
    if (snprintf(buf, MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->minFreq * THOUSAND) < 0) {
        return 1;
    }

    char minFreqFile[MAX_NAME_LEN] = {0};
    const char min1[] = "/sys/devices/system/cpu/cpufreq/";
    const char min2[] = "/scaling_min_freq";
    for (i = 0; i < poNum; i++) {
        StrCopy(minFreqFile, min1, MAX_NAME_LEN);
        strncat(minFreqFile, policys[i], strlen(policys[i]));
        strncat(minFreqFile, min2, strlen(min2));
        if (WriteFile(minFreqFile, buf, strlen(buf)) != 0) {
            return 1;
        }
    }

    // set max freq
    if (snprintf(buf, MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->maxFreq * THOUSAND) < 0) {
        return 1;
    }
    char maxFreqFile[MAX_NAME_LEN] = {0};
    const char max1[] = "/sys/devices/system/cpu/cpufreq/";
    const char max2[] = "/scaling_max_freq";
    for (i = 0; i < poNum; i++) {
        StrCopy(maxFreqFile, max1, MAX_NAME_LEN);
        strncat(maxFreqFile, policys[i], strlen(policys[i]));
        strncat(maxFreqFile, max2, strlen(max2));
        if (WriteFile(maxFreqFile, buf, strlen(buf)) != 0) {
            return 1;
        }
    }
    return 0;
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
    int rspCode = CurrentGovernorRead(rstData);
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
    int rspCode = 0;
    if (req->head.dataLen > 0 && req->data != NULL) {
        // spec = 1
        PWR_CPU_CurFreq *target = (PWR_CPU_CurFreq *)req->data;
        poNum = req->head.dataLen / sizeof(PWR_CPU_CurFreq);
        MergeDuplicatePolicys(target, &poNum);
        if (CheckPolicys(target, poNum) != 0) {
            rspCode = ERR_POLICY_INVALIDE;
        } else if (InputTargetPolicys(target, policys, poNum) != 0) {
            rspCode = ERR_COMMON;
        }
    } else if (req->head.dataLen > 0) {
        rspCode = ERR_INVALIDE_PARAM;
    } else if (GetPolicys(policys, &poNum) != 0) {
        // spec = 0
        rspCode = ERR_COMMON;
    }
    if (rspCode != 0) {
        SendRspToClient(req, rspCode, NULL, 0);
        return;
    }
    PWR_CPU_CurFreq *rstData = malloc(sizeof(PWR_CPU_CurFreq) * poNum);
    if (!rstData) {
        return;
    }
    rspCode = FreqRead(rstData, policys, &poNum);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_CurFreq) * poNum);
}

void SetCpuFreq(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Set Freq  Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    size_t len = (req->head.dataLen) / sizeof(PWR_CPU_CurFreq);
    char currentGov[MAX_ELEMENT_NAME_LEN];
    PWR_CPU_CurFreq *target = (PWR_CPU_CurFreq *)req->data;
    int rspCode = 0;

    // check whether current governor is userspace
    if (CurrentGovernorRead(currentGov) != SUCCESS) {
        rspCode = ERR_COMMON;
    } else if (CheckPolicys(target, len) == 1) {
        rspCode = ERR_POLICY_INVALIDE;
    } else if (strcmp(currentGov, "userspace") != 0) {
        rspCode = ERR_GOVERNOR_INVALIDE;
    }

    // check whether frequency is in range
    PWR_CPU_FreqRange freqRange;
    if (FreqRangeRead(&freqRange) != 0) {
        rspCode = ERR_COMMON;
    } else if (CheckFreqInRange(target, len, freqRange) != 0) {
        rspCode = ERR_FREQ_NOT_IN_RANGE;
    }

    if (rspCode != 0) {
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        rspCode = FreqSet(target, len);
        SendRspToClient(req, rspCode, NULL, 0);
    }
}

void GetCpuFreqAbility(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get GetCpuFreqAbility Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    int coreNum = GetCpuCoreNumber();
    char policys[MAX_CPU_LIST_LEN][MAX_ELEMENT_NAME_LEN];
    bzero(policys, sizeof(policys));
    int poNum;
    if (GetPolicys(policys, &poNum) != SUCCESS) {
        int rspCode = ERR_COMMON;
        SendRspToClient(req, rspCode, NULL, 0);
        return;
    }
    int step = (coreNum / poNum) * MAX_CPU_ID_WIDTH + sizeof(int);
    PWR_CPU_FreqAbility *rstData = malloc(sizeof(PWR_CPU_FreqAbility) + step * poNum);
    if (!rstData) {
        return;
    }
    bzero(rstData, sizeof(PWR_CPU_FreqAbility) + step * poNum);
    rstData->freqDomainNum = poNum;
    rstData->freqDomainStep = step;
    int rspCode = FreqAbilityRead(rstData, policys);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_FreqAbility) + step * poNum);
}

void GetCpuFreqRange(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get GetCpuFreqRange Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);

    PWR_CPU_FreqRange *rstData = malloc(sizeof(PWR_CPU_FreqRange));
    if (!rstData) {
        return;
    }
    int rspCode = FreqRangeRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_FreqRange));
}

void SetCpuFreqRange(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get SetCpuFreqRange Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);

    PWR_CPU_FreqRange *rstData = (PWR_CPU_FreqRange *)req->data;

    int rspCode = FreqRangeSet(rstData);
    SendRspToClient(req, rspCode, NULL, 0);
}

// Total CPU cores
int GetCpuCoreNumber(void)
{
    return sysconf(_SC_NPROCESSORS_CONF);
}
