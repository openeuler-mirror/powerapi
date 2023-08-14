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

const char cpuAttributes[PWR_MAX_ARRRIBUTES][PWR_MAX_NAME_LEN] = {
    "Architecture", "Model name", "Byte Order", "NUMA node(s)", "NUMA node", "CPU(s)",
    "On-line CPU", "Thread(s) per core", "Core(s) per socket", "max MHz", "min MHz"
};

int GetCpuArrId(char *att)
{
    int i;
    for (i = 0; i < PWR_MAX_ARRRIBUTES; i++) {
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
        case PWR_ARCH:
            StrCopy(rstData->arch, value, PWR_MAX_ELEMENT_NAME_LEN);
            break;
        case PWR_MODEL_NAME:
            StrCopy(rstData->modelName, value, PWR_MAX_NAME_LEN);
            break;
        case PWR_BYTE_OR:
            if (strstr(value, "Little") != NULL) {
                rstData->byteOrder = 0;
            } else {
                rstData->byteOrder = 1;
            }
            break;
        case PWR_NUMA_NUMBER:
            rstData->numaNum = atoi(value);
            break;
        case PWR_NUMA_NODE:
            DeleteSubstr(att, "NUMA node");
            DeleteSubstr(att, " CPU(s)");
            int j = atoi(att);
            rstData->numa[j].nodeNo = j;
            StrCopy(rstData->numa[j].cpuList, value, PWR_MAX_CPU_LIST_LEN);
            break;
        case PWR_CPU_NUMBER:
            if (strlen(att) == PWR_CPUS_WIDTH) {
                rstData->coreNum = atoi(value);
            }
            break;
        case PWR_ONLINE_CPU:
            StrCopy(rstData->onlineList, value, PWR_MAX_CPU_LIST_LEN);
            break;
        case PWR_THREADS_PER_CORE:
            rstData->threadsPerCore = atoi(value);
            break;
        case PWR_CORES_PER_SOCKET:
            rstData->coresperSocket = atoi(value);
            break;
        case PWR_MAX_MHZ:
            rstData->maxFreq = atof(value);
            break;
        case PWR_MIN_MHZ:
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
    char buf[PWR_MAX_STRING_LEN];
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
    return PWR_SUCCESS;
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
    char temp[PWR_MAX_STRING_LEN];
    while (i <= PWR_CPU_USAGE_COLUMN) {
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

static void CalculateUsage(PWR_CPU_Usage *rstData, unsigned long paras[2][PWR_CPU_USAGE_COLUMN], int i)
{
    unsigned long parasSum1 = 0;
    unsigned long parasSum2 = 0;
    int j;
    for (j = 1; j < PWR_CPU_USAGE_COLUMN; j++) {
        parasSum1 += paras[0][j];
        parasSum2 += paras[1][j];
    }
    if (i == 0) {
        rstData->avgUsage =
            1 - ((double)(paras[1][PWR_CPU_IDLE_COLUMN] - paras[0][PWR_CPU_IDLE_COLUMN])) / (parasSum2 - parasSum1);
    } else {
        rstData->coreUsage[paras[0][0]].coreNo = paras[0][0];
        rstData->coreUsage[paras[0][0]].usage =
            1 - ((double)(paras[1][PWR_CPU_IDLE_COLUMN] - paras[0][PWR_CPU_IDLE_COLUMN])) / (parasSum2 - parasSum1);
    }
}

int CPUUsageRead(PWR_CPU_Usage *rstData, int coreNum)
{
    const char usage[] = "cat /proc/stat";
    unsigned long paras[2][PWR_CPU_USAGE_COLUMN];
    FILE *fp1 = popen(usage, "r");
    if (fp1 == NULL) {
        return PWR_ERR_COMMON;
    }
    usleep(PWR_LATENCY);
    FILE *fp2 = popen(usage, "r");
    if (fp2 == NULL) {
        pclose(fp1);
        return PWR_ERR_COMMON;
    }
    char buf1[PWR_MAX_STRING_LEN] = {0};
    char buf2[PWR_MAX_STRING_LEN] = {0};
    int i = 0;
    rstData->coreNum = coreNum;
    while (i < coreNum + 1) {
        if (fgets(buf1, sizeof(buf1) - 1, fp1) == NULL) {
            pclose(fp1);
            pclose(fp2);
            return PWR_ERR_COMMON;
        }
        if (fgets(buf2, sizeof(buf2) - 1, fp2) == NULL) {
            pclose(fp1);
            pclose(fp2);
            return PWR_ERR_COMMON;
        }
        if (UsageToLong(buf1, paras[0], i) != UsageToLong(buf2, paras[1], i)) {
            pclose(fp1);
            pclose(fp2);
            return PWR_ERR_COMMON;
        }
        CalculateUsage(rstData, paras, i);
        i++;
    }
    pclose(fp1);
    pclose(fp2);
    return PWR_SUCCESS;
}

int PerfDataRead(PWR_CPU_PerfData *perfData)
{
    int m = GetArch();
    char *missStr;
    if (m == PWR_AARCH_64) {
        missStr = "perf stat -e r0033 -e instructions -e cycles -a sleep 0.1 &>perf.txt";
    } else if (m == PWR_X86_64) {
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
    char buf[PWR_MAX_STRING_LEN];
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
            cacheMiss += strtoul(buf, NULL, PWR_DECIMAL);
        } else if (strstr(buf, "instructions") != NULL) {
            DeleteSubstr(buf, "instructions");
            ins += strtoul(buf, NULL, PWR_DECIMAL);
        } else if (strstr(buf, "cycles") != NULL) {
            DeleteSubstr(buf, "cycles");
            cycles += strtoul(buf, NULL, PWR_DECIMAL);
        }
    }
    perfData->llcMiss = (double)cacheMiss / ins;
    perfData->ipc = (double)ins / cycles;
    pclose(fp);
    return PWR_SUCCESS;
}

int GetPolicys(char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int *poNum)
{
    FILE *fp = NULL;
    char policyInfo[] = "ls /sys/devices/system/cpu/cpufreq | grep policy";
    fp = popen(policyInfo, "r");
    if (fp == NULL) {
        return 1;
    }
    char buf[PWR_MAX_NAME_LEN];
    bzero(buf, sizeof(buf));
    *poNum = 0;
    while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
        DeleteChar(buf, '\n');
        StrCopy(policys[*poNum], buf, PWR_MAX_ELEMENT_NAME_LEN);
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

/**
 * CheckPolicys - check if the target policy is valid
*/
static int CheckPolicys(PWR_CPU_CurFreq *target, int num)
{
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN];
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
        for (i = 0; i < num; i++) {
            if (InIntRange(policysId, poNum, target[i].policyId) == 1) {
                return PWR_ERR_INVALIDE_PARAM;
            }
        }
        return 0;
    }
    return 1;
}

static int InputTargetPolicys(PWR_CPU_CurFreq *target, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int poNum)
{
    char buffer[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    for (int i = 0; i < poNum; i++) {
        StrCopy(policys[i], "policy", PWR_MAX_ELEMENT_NAME_LEN);
        if (snprintf(buffer, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", target[i].policyId) < 0) {
            return 1;
        }
        strncat(policys[i], buffer, strlen(buffer));
    }
    return 0;
}

static int AllGovernorsRead(char (*govList)[PWR_MAX_ELEMENT_NAME_LEN], int *govNum)
{
    char buf[PWR_MAX_ELEMENT_NAME_LEN * PWR_MAX_GOV_NUM] = {0};
    const char govInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_available_governors";
    int fd = open(govInfo, O_RDONLY);
    if (fd == -1) {
        return 1;
    }
    if (read(fd, buf, PWR_MAX_ELEMENT_NAME_LEN * PWR_MAX_GOV_NUM - 1) <= 0) {
        close(fd);
        return 1;
    }
    close(fd);
    DeleteChar(buf, '\n');
    char *temp = strtok(buf, " ");
    *govNum = 0;
    while (temp != NULL) {
        DeleteChar(temp, ' ');
        StrCopy(govList[(*govNum)++], temp, PWR_MAX_ELEMENT_NAME_LEN);
        temp = strtok(NULL, " ");
    }
    return 0;
}

static int CheckAvailableGovernor(char *gov, char *policys)
{
    char *checkGovInfo = malloc(strlen(gov) + PWR_MAX_NAME_LEN);
    if (checkGovInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    const char s1[] = "cat /sys/devices/system/cpu/cpufreq/";
    const char s2[] = "/scaling_available_governors";
    StrCopy(checkGovInfo, s1, strlen(gov) + PWR_MAX_NAME_LEN);
    strncat(checkGovInfo, policys, strlen(gov));
    strncat(checkGovInfo, s2, strlen(s2));
    char buf[PWR_MAX_STRING_LEN];
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
    char buf[PWR_MAX_STRING_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
        pclose(fp);
        return PWR_ERR_COMMON;
    }
    DeleteChar(buf, '\n');
    DeleteChar(buf, ' ');
    StrCopy(rstData, buf, PWR_MAX_ELEMENT_NAME_LEN);
    pclose(fp);
    return PWR_SUCCESS;
}

int GovernorSet(char *gov, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int *poNum)
{
    int i;
    for (i = 0; i < (*poNum); i++) {
        if (CheckAvailableGovernor(gov, policys[i]) != 0) {
            return PWR_ERR_INVALIDE_PARAM;
        }
    }
    char *govInfo = malloc(strlen(gov) + PWR_MAX_NAME_LEN);
    if (govInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    static const char s1[] = "echo ";
    static const char s2[] = "> /sys/devices/system/cpu/cpufreq/";
    static const char s3[] = "/scaling_governor";
    for (i = 0; i < (*poNum); i++) {
        StrCopy(govInfo, s1, strlen(gov) + PWR_MAX_NAME_LEN);
        strncat(govInfo, gov, strlen(gov));
        strncat(govInfo, s2, strlen(s2));
        strncat(govInfo, policys[i], strlen(policys[i]));
        strncat(govInfo, s3, strlen(s3));
        FILE *fp = popen(govInfo, "r");
        if (fp == NULL) {
            free(govInfo);
            return PWR_ERR_COMMON;
        }
        pclose(fp);
        // todo: write back precious governor
    }
    return PWR_SUCCESS;
}

/**
 * FreqRead - get target policy freq based on the given policys
 * @policys: target policys
 * @poNum:   valid policys num
*/
static int FreqRead(PWR_CPU_CurFreq *rstData, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int *poNum)
{
    int m = GetArch();
    char freqInfo[PWR_MAX_NAME_LEN] = {0};
    static const char s1[] = "cat /sys/devices/system/cpu/cpufreq/";
    static const char s2Arm[] = "/cpuinfo_cur_freq";
    static const char s2X86[] = "/scaling_cur_freq";
    char s2[PWR_MAX_ELEMENT_NAME_LEN];
    bzero(s2, sizeof(s2));
    if (m == PWR_AARCH_64) {
        StrCopy(s2, s2Arm, PWR_MAX_ELEMENT_NAME_LEN);
    } else if (m == PWR_X86_64) {
        StrCopy(s2, s2X86, PWR_MAX_ELEMENT_NAME_LEN);
    }
    char buf[PWR_MAX_STRING_LEN];
    int i;
    for (i = 0; i < (*poNum); i++) {
        StrCopy(freqInfo, s1, PWR_MAX_NAME_LEN);
        strncat(freqInfo, policys[i], strlen(policys[i]));
        strncat(freqInfo, s2, strlen(s2));
        FILE *fp = popen(freqInfo, "r");
        if (fp == NULL) {
            return 1;
        }
        if (fgets(buf, sizeof(buf) - 1, fp) == NULL) {
            pclose(fp);
            return PWR_ERR_COMMON;
        }
        DeleteChar(buf, '\n');
        DeleteChar(buf, ' ');
        DeleteSubstr(policys[i], "policy");
        pclose(fp);
        rstData[i].policyId = atoi(policys[i]);
        rstData[i].curFreq = (double)strtoul(buf, NULL, PWR_DECIMAL) / PWR_CONVERSION;
    }
    FreqSortByPolicy(rstData, (*poNum));
    return PWR_SUCCESS;
}

static int FreqSet(PWR_CPU_CurFreq *target, int num)
{
    char setFreqInfo[PWR_MAX_NAME_LEN] = {0};
    static const char s1[] = "echo ";
    static const char s2[] = " > /sys/devices/system/cpu/cpufreq/policy";
    static const char s3[] = "/scaling_setspeed";
    int i, freq;
    char buffer[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    for (i = 0; i < num; i++) {
        StrCopy(setFreqInfo, s1, PWR_MAX_NAME_LEN);
        freq = (int)target[i].curFreq * THOUSAND;
        if (snprintf(buffer, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", freq) < 0) {
            return PWR_ERR_COMMON;
        }
        strncat(setFreqInfo, buffer, strlen(buffer));
        strncat(setFreqInfo, s2, strlen(s2));
        if (snprintf(buffer, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", target[i].policyId) < 0) {
            return PWR_ERR_COMMON;
        }
        strncat(setFreqInfo, buffer, strlen(buffer));
        strncat(setFreqInfo, s3, strlen(s3));
        FILE *fp = popen(setFreqInfo, "r");
        if (fp == NULL) {
            return PWR_ERR_COMMON;
        }
        pclose(fp);
    }
    return PWR_SUCCESS;
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

static int FreqDomainRead(char *buf, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int domainNum, int step)
{
    char domainInfo[PWR_MAX_NAME_LEN] = {0};
    char domainbuf[PWR_MAX_CPU_LIST_LEN] = {0};
    char temp[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    char s1[] = "/sys/devices/system/cpu/cpufreq/";
    char s2[] = "/affected_cpus";
    int i;
    for (i = 0; i < domainNum; i++) {
        StrCopy(domainInfo, s1, PWR_MAX_NAME_LEN);
        strncat(domainInfo, policys[i], strlen(policys[i]));
        strncat(domainInfo, s2, strlen(s2));
        int fd = open(domainInfo, O_RDONLY);
        if (fd == -1) {
            close(fd);
            return 1;
        }
        if (read(fd, domainbuf, PWR_MAX_CPU_LIST_LEN - 1) <= 0) {
            close(fd);
            return 1;
        }
        close(fd);
        DeleteChar(domainbuf, '\n');
        // convert policys to int
        StrCopy(temp, policys[i], PWR_MAX_ELEMENT_NAME_LEN);
        DeleteSubstr(temp, "policy");
        buf[i * step] = atoi(temp);
        StrCopy(buf + i * step + sizeof(int), domainbuf, step - sizeof(int));
    }
    return 0;
}


static int FreqAbilityRead(PWR_CPU_FreqAbility *rstData, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN])
{
    if (FreqDriverRead(rstData->curDriver, PWR_MAX_ELEMENT_NAME_LEN) != PWR_SUCCESS) {
        return PWR_ERR_COMMON;
    }
    if (AllGovernorsRead(rstData->avGovList, &(rstData->avGovNum)) != PWR_SUCCESS) {
        return PWR_ERR_COMMON;
    }
    if (FreqDomainRead(rstData->freqDomain, policys, rstData->freqDomainNum, rstData->freqDomainStep) != PWR_SUCCESS) {
        return PWR_ERR_COMMON;
    }
}

static int CheckFreqInRange(PWR_CPU_CurFreq *target, int num, PWR_CPU_FreqRange freqRange)
{
    for (int i = 0; i < num; i++) {
        if (target[i].curFreq < freqRange.minFreq || target[i].curFreq > freqRange.maxFreq) {
            return PWR_ERR_INVALIDE_PARAM;
        }
    }
    return 0;
}

static int ScalingFreqRangeRead(PWR_CPU_FreqRange *rstData)
{
    char buf[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    const char minFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq";
    const char maxFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq";
    if (ReadFile(minFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    rstData->minFreq = atoi(buf) / THOUSAND;
    if (ReadFile(maxFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    rstData->maxFreq = atoi(buf) / THOUSAND;
    return 0;
}

static int CpuFreqRangeRead(PWR_CPU_FreqRange *cpuFreqRange)
{
    char buf[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    const char minFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_min_freq";
    const char maxFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq";
    if (ReadFile(minFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    cpuFreqRange->minFreq = atoi(buf) / THOUSAND;
    if (ReadFile(maxFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    cpuFreqRange->maxFreq = atoi(buf) / THOUSAND;
    return 0;
}

static int FreqRangeSet(PWR_CPU_FreqRange *rstData)
{
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN] = {0};
    int ret = -1;
    int poNum, i;
    if (GetPolicys(policys, &poNum) != 0) {
        return PWR_ERR_COMMON;
    }
    char buf[PWR_MAX_ELEMENT_NAME_LEN] = {0};

    PWR_CPU_FreqRange cpuFreqRange = {0};
    if (CpuFreqRangeRead(&cpuFreqRange) != PWR_SUCCESS) {
        return PWR_ERR_COMMON;
    }
    if (rstData->minFreq < cpuFreqRange.minFreq ||
        rstData->maxFreq > cpuFreqRange.maxFreq) {
        Logger(ERROR, MD_NM_SVR_CPU, "cpu freq range: [%d, %d]. the input minfreq[%d] "
            "or maxfreq[%d] is invalide", cpuFreqRange.minFreq, cpuFreqRange.maxFreq,
            rstData->minFreq, rstData->maxFreq);
        return PWR_ERR_INVALIDE_PARAM;
    }

    // set min freq
    if (snprintf(buf, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->minFreq * THOUSAND) < 0) {
        return PWR_ERR_FILE_SPRINTF_FIILED;
    }

    char minFreqFile[PWR_MAX_NAME_LEN] = {0};
    const char min1[] = "/sys/devices/system/cpu/cpufreq/";
    const char min2[] = "/scaling_min_freq";
    for (i = 0; i < poNum; i++) {
        StrCopy(minFreqFile, min1, PWR_MAX_NAME_LEN);
        strncat(minFreqFile, policys[i], strlen(policys[i]));
        strncat(minFreqFile, min2, strlen(min2));
        ret = WriteFile(minFreqFile, buf, strlen(buf));
        if (ret != 0) {
            return ret;
        }
    }

    // set max freq
    if (snprintf(buf, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->maxFreq * THOUSAND) < 0) {
        return PWR_ERR_FILE_SPRINTF_FIILED;
    }
    char maxFreqFile[PWR_MAX_NAME_LEN] = {0};
    const char max1[] = "/sys/devices/system/cpu/cpufreq/";
    const char max2[] = "/scaling_max_freq";
    for (i = 0; i < poNum; i++) {
        StrCopy(maxFreqFile, max1, PWR_MAX_NAME_LEN);
        strncat(maxFreqFile, policys[i], strlen(policys[i]));
        strncat(maxFreqFile, max2, strlen(max2));
        ret = WriteFile(maxFreqFile, buf, strlen(buf));
        if (ret != 0) {
            return ret;
        }
    }
    return PWR_SUCCESS;
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
    char *rstData = malloc(sizeof(char) * PWR_MAX_ELEMENT_NAME_LEN);
    if (!rstData) {
        return;
    }
    int rspCode = CurrentGovernorRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(char) * PWR_MAX_ELEMENT_NAME_LEN);
}

void SetCpuFreqGovernor(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Set Freq Governor Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN];
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
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN];
    bzero(policys, sizeof(policys));
    int poNum;
    int rspCode = 0;
    if (req->head.dataLen > 0 && req->data != NULL) {
        // spec = 1
        PWR_CPU_CurFreq *target = (PWR_CPU_CurFreq *)req->data;
        poNum = req->head.dataLen / sizeof(PWR_CPU_CurFreq);
        MergeDuplicatePolicys(target, &poNum);
        if (CheckPolicys(target, poNum) != 0) {
            rspCode = PWR_ERR_POLICY_INVALIDE;
        } else if (InputTargetPolicys(target, policys, poNum) != 0) {
            rspCode = PWR_ERR_COMMON;
        }
    } else if (req->head.dataLen > 0) {
        rspCode = PWR_ERR_INVALIDE_PARAM;
    } else if (GetPolicys(policys, &poNum) != 0) {
        // spec = 0
        rspCode = PWR_ERR_COMMON;
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
    size_t num = (req->head.dataLen) / sizeof(PWR_CPU_CurFreq);
    char currentGov[PWR_MAX_ELEMENT_NAME_LEN];
    PWR_CPU_CurFreq *target = (PWR_CPU_CurFreq *)req->data;
    int rspCode = 0;

    // check whether current governor is userspace
    if (CurrentGovernorRead(currentGov) != PWR_SUCCESS) {
        rspCode = PWR_ERR_COMMON;
    } else if (CheckPolicys(target, num) == 1) {
        rspCode = PWR_ERR_POLICY_INVALIDE;
    } else if (strcmp(currentGov, "userspace") != 0) {
        rspCode = PWR_ERR_GOVERNOR_INVALIDE;
    }

    // check whether frequency is in range
    PWR_CPU_FreqRange freqRange;
    if (ScalingFreqRangeRead(&freqRange) != 0) {
        rspCode = PWR_ERR_COMMON;
    } else if (CheckFreqInRange(target, num, freqRange) != 0) {
        rspCode = PWR_ERR_FREQ_NOT_IN_RANGE;
    }

    if (rspCode != 0) {
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        rspCode = FreqSet(target, num);
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
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN];
    bzero(policys, sizeof(policys));
    int poNum;
    if (GetPolicys(policys, &poNum) != PWR_SUCCESS) {
        int rspCode = PWR_ERR_COMMON;
        SendRspToClient(req, rspCode, NULL, 0);
        return;
    }
    int step = (coreNum / poNum) * PWR_MAX_CPU_ID_WIDTH + sizeof(int);
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
    int rspCode = ScalingFreqRangeRead(rstData);
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
