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
    char buf[PWR_MAX_STRING_LEN] = {0};
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
    bzero(cpuInfo, sizeof(PWR_CPU_Info));
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
    unsigned long paras[2][PWR_CPU_USAGE_COLUMN] = {0};
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
    char buf[PWR_MAX_STRING_LEN] = {0};
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
    const char *targetItem = "policy";
    const size_t len = strlen(targetItem);
    DIR *dir = NULL;
    struct dirent *ent;
    char policyInfo[] = "/sys/devices/system/cpu/cpufreq";
    dir = opendir(policyInfo);
    if (dir == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Unable to open direct: %s", policyInfo);
        return PWR_ERR_COMMON;
    }

    char buf[PWR_MAX_NAME_LEN];
    bzero(buf, PWR_MAX_NAME_LEN);
    *poNum = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (strlen(ent->d_name) <= len || strncmp(ent->d_name, targetItem, len) != 0) {
            continue;
        }

        bzero(buf, PWR_MAX_NAME_LEN);
        strncpy(buf, ent->d_name, PWR_MAX_NAME_LEN);
        DeleteChar(buf, '\n');
        StrCopy(policys[*poNum], buf, PWR_MAX_ELEMENT_NAME_LEN);
        (*poNum)++;
    }

    closedir(dir);
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
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN] = {0};
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
        strcat(policys[i], buffer);
    }
    return 0;
}

static int AllGovernorsRead(char (*govList)[PWR_MAX_ELEMENT_NAME_LEN], int *govNum)
{
    int len = PWR_MAX_ELEMENT_NAME_LEN * PWR_MAX_GOV_NUM;
    char buf[len];
    const char govInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_available_governors";

    bzero(buf, len);
    int ret = ReadFile(govInfo, buf, len);
    if (ret != 0) {
        return ret;
    }

    char *temp = strtok(buf, " ");
    *govNum = 0;
    while (temp != NULL) {
        DeleteChar(temp, ' ');
        StrCopy(govList[(*govNum)++], temp, PWR_MAX_ELEMENT_NAME_LEN);
        temp = strtok(NULL, " ");
    }
    return 0;
}

static int CheckAvailableGovernor(const char *gov, char *policys)
{
    char *checkGovInfo = malloc(strlen(gov) + PWR_MAX_NAME_LEN);
    if (checkGovInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    const char s1[] = "/sys/devices/system/cpu/cpufreq/";
    const char s2[] = "/scaling_available_governors";
    StrCopy(checkGovInfo, s1, strlen(gov) + PWR_MAX_NAME_LEN);
    strcat(checkGovInfo, policys);
    strcat(checkGovInfo, s2);
    char buf[PWR_MAX_STRING_LEN] = {0};
    int ret = ReadFile(checkGovInfo, buf, PWR_MAX_STRING_LEN);
    if (ret != PWR_SUCCESS) {
        free(checkGovInfo);
        return ret;
    }

    char *temp = strtok(buf, " ");
    while (temp != NULL) {
        DeleteChar(temp, ' ');
        if (strcmp(temp, gov) == 0) {
            free(checkGovInfo);
            return 0;
        }
        temp = strtok(NULL, " ");
    }
    free(checkGovInfo);
    return 1;
}

int CurrentGovernorRead(char *gov)
{
    char govInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor";
    char buf[PWR_MAX_STRING_LEN] = {0};
    int ret = ReadFile(govInfo, buf, PWR_MAX_STRING_LEN);
    if (ret != PWR_SUCCESS) {
        return ret;
    }

    DeleteChar(buf, ' ');
    StrCopy(gov, buf, PWR_MAX_ELEMENT_NAME_LEN);
    return PWR_SUCCESS;
}

static int GovernorSet(const char *gov, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int *poNum)
{
    int i;
    for (i = 0; i < (*poNum); i++) {
        if (CheckAvailableGovernor(gov, policys[i]) != 0) {
            return PWR_ERR_INVALIDE_PARAM;
        }
    }
    int buffLen = PWR_MAX_NAME_LEN + strlen(gov);
    char *govInfo = malloc(buffLen);
    if (govInfo == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        return 1;
    }
    bzero(govInfo, buffLen);
    static const char s1[] = "/sys/devices/system/cpu/cpufreq/";
    static const char s2[] = "/scaling_governor";
    for (i = 0; i < (*poNum); i++) {
        StrCopy(govInfo, s1, buffLen);
        strcat(govInfo, policys[i]);
        strcat(govInfo, s2);
        int ret = WriteFile(govInfo, gov, strlen(gov));
        if (ret != 0) {
            Logger(ERROR, MD_NM_SVR_CPU, "Change gov(%s) failed.", gov);
            free(govInfo);
            return ret;
        }
    }
    free(govInfo);
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
    char buf[PWR_MAX_STRING_LEN] = {0};
    const char s1[] = "/sys/devices/system/cpu/cpufreq/";
    const char s2Arm[] = "/cpuinfo_cur_freq";
    const char s2X86[] = "/scaling_cur_freq";
    char s2[PWR_MAX_ELEMENT_NAME_LEN];
    bzero(s2, sizeof(s2));
    if (m == PWR_AARCH_64) {
        StrCopy(s2, s2Arm, PWR_MAX_ELEMENT_NAME_LEN);
    } else if (m == PWR_X86_64) {
        StrCopy(s2, s2X86, PWR_MAX_ELEMENT_NAME_LEN);
    }

    for (int i = 0; i < (*poNum); i++) {
        StrCopy(freqInfo, s1, PWR_MAX_NAME_LEN);
        strcat(freqInfo, policys[i]);
        strcat(freqInfo, s2);
        int ret = ReadFile(freqInfo, buf, PWR_MAX_STRING_LEN);
        if (ret != PWR_SUCCESS) {
            return ret;
        }

        DeleteChar(buf, ' ');
        DeleteSubstr(policys[i], "policy");
        rstData[i].policyId = atoi(policys[i]);
        rstData[i].curFreq = (double)strtoul(buf, NULL, PWR_DECIMAL) / PWR_CONVERSION;
    }
    FreqSortByPolicy(rstData, (*poNum));
    return PWR_SUCCESS;
}

static int FreqSet(PWR_CPU_CurFreq *target, int num)
{
    char setFreqInfo[PWR_MAX_NAME_LEN] = {0};
    const char s1[] = "/sys/devices/system/cpu/cpufreq/policy";
    const char s2[] = "/scaling_setspeed";
    int i, freq, ret;
    char bufFreq[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    char bufPolicyId[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    for (i = 0; i < num; i++) {
        StrCopy(setFreqInfo, s1, PWR_MAX_NAME_LEN);
        freq = (int)target[i].curFreq * THOUSAND;
        if (snprintf(bufFreq, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", freq) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        if (snprintf(bufPolicyId, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", target[i].policyId) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        strcat(setFreqInfo, bufPolicyId);
        strcat(setFreqInfo, s2);
        ret = WriteFile(setFreqInfo, bufFreq, strlen(bufFreq));
        if (ret != 0) {
            return ret;
        }
    }
    return PWR_SUCCESS;
}

static int FreqDriverRead(char *buf, int bufLen)
{
    const char driverInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_driver";
    return ReadFile(driverInfo, buf, bufLen);
}

static int FreqDomainRead(char *buf, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int domainNum, int step)
{
    char domainInfo[PWR_MAX_NAME_LEN] = {0};
    char domainbuf[PWR_MAX_CPU_LIST_LEN] = {0};
    char temp[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    const char s1[] = "/sys/devices/system/cpu/cpufreq/";
    const char s2[] = "/affected_cpus";
    for (int i = 0; i < domainNum; i++) {
        StrCopy(domainInfo, s1, PWR_MAX_NAME_LEN);
        strcat(domainInfo, policys[i]);
        strcat(domainInfo, s2);
        bzero(domainbuf, PWR_MAX_CPU_LIST_LEN);
        int ret = ReadFile(domainInfo, domainbuf, PWR_MAX_CPU_LIST_LEN);
        if (ret != PWR_SUCCESS) {
            return ret;
        }

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
    return PWR_SUCCESS;
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
    int ret = -1;
    const char minFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq";
    const char maxFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq";
    ret = ReadFile(minFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    rstData->minFreq = atoi(buf) / THOUSAND;
    ret = ReadFile(maxFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    rstData->maxFreq = atoi(buf) / THOUSAND;
    return 0;
}

static int CpuFreqRangeRead(PWR_CPU_FreqRange *cpuFreqRange)
{
    char buf[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    int ret = -1;
    const char minFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_min_freq";
    const char maxFreqInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq";
    ret = ReadFile(minFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    cpuFreqRange->minFreq = atoi(buf) / THOUSAND;
    ret = ReadFile(maxFreqInfo, buf, PWR_MAX_ELEMENT_NAME_LEN);
    if (ret != PWR_SUCCESS) {
        return ret;
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
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    char minFreqFile[PWR_MAX_NAME_LEN] = {0};
    const char min1[] = "/sys/devices/system/cpu/cpufreq/";
    const char min2[] = "/scaling_min_freq";
    for (i = 0; i < poNum; i++) {
        StrCopy(minFreqFile, min1, PWR_MAX_NAME_LEN);
        strcat(minFreqFile, policys[i]);
        strcat(minFreqFile, min2);
        ret = WriteFile(minFreqFile, buf, strlen(buf));
        if (ret != 0) {
            return ret;
        }
    }

    // set max freq
    if (snprintf(buf, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->maxFreq * THOUSAND) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }
    char maxFreqFile[PWR_MAX_NAME_LEN] = {0};
    const char max1[] = "/sys/devices/system/cpu/cpufreq/";
    const char max2[] = "/scaling_max_freq";
    for (i = 0; i < poNum; i++) {
        StrCopy(maxFreqFile, max1, PWR_MAX_NAME_LEN);
        strcat(maxFreqFile, policys[i]);
        strcat(maxFreqFile, max2);
        ret = WriteFile(maxFreqFile, buf, strlen(buf));
        if (ret != 0) {
            return ret;
        }
    }
    return PWR_SUCCESS;
}

static int GetGovAttrs(PWR_CPU_FreqGovAttrs *attrs)
{
    char base[] = "/sys/devices/system/cpu/cpufreq/";
    char attrPath[PWR_MAX_NAME_LEN] = {0};
    StrCopy(attrPath, base, PWR_MAX_NAME_LEN - 1);
    strcat(attrPath, attrs->gov);
    DIR *dir = opendir(attrPath);
    if (dir == NULL) {
        Logger(ERROR, MD_NM_SVR_CPU, "Unable to open direct: %s", attrPath);
        return PWR_ERR_FILE_OPEN_FAILED;
    }
    char *pathEnd = attrPath + strlen(attrPath);
    *pathEnd = PATH_SEP_CHAR;
    pathEnd++;
    struct dirent *dt;
    int ret = PWR_SUCCESS;
    while ((dt = readdir(dir)) != NULL && attrs->attrNum < PWR_MAX_GOV_ATTR_NUM) {
        if (strcmp(dt->d_name, CURRENT_DIR) == 0 || strcmp(dt->d_name, PARENT_DIR) == 0) {
            continue;
        }
        StrCopy(attrs->attrs[attrs->attrNum].key, dt->d_name, PWR_MAX_ELEMENT_NAME_LEN);
        StrCopy(pathEnd, dt->d_name, PWR_MAX_ELEMENT_NAME_LEN);
        ret = ReadFile(attrPath, attrs->attrs[attrs->attrNum].value, PWR_MAX_VALUE_LEN);
        if (ret != PWR_SUCCESS) {
            break;
        }
        attrs->attrNum++;
    }
    closedir(dir);
    return ret;
}

static int GetGovAttr(PWR_CPU_FreqGovAttr *attr)
{
    char base[] = "/sys/devices/system/cpu/cpufreq/";
    char attrPath[PWR_MAX_NAME_LEN] = {0};
    StrCopy(attrPath, base, PWR_MAX_NAME_LEN - 1);
    strcat(attrPath, attr->gov);
    strcat(attrPath, PATH_SEP_STR);
    strcat(attrPath, attr->attr.key);
    int ret = ReadFile(attrPath, attr->attr.value, sizeof(attr->attr.value));
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_CPU, "GetGovAttr failed. path:%s, value:%s, ret:%d",
            attrPath, attr->attr.value, ret);
    }
    return ret;
}

static int SetGovAttr(PWR_CPU_FreqGovAttr *attr)
{
    char base[] = "/sys/devices/system/cpu/cpufreq/";
    char attrPath[PWR_MAX_NAME_LEN] = {0};
    StrCopy(attrPath, base, PWR_MAX_NAME_LEN - 1);
    strcat(attrPath, attr->gov);
    strcat(attrPath, PATH_SEP_STR);
    strcat(attrPath, attr->attr.key);
    int ret = WriteFile(attrPath, attr->attr.value, strlen(attr->attr.value));
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_CPU, "SetGovAttr failed. path:%s, ret:%d", attrPath, ret);
    }
    return ret;
}

#define CPU_IDLE_PATH           "/sys/devices/system/cpu/cpuidle"
#define CPU_IDLE_DRV_PATH       "/sys/devices/system/cpu/cpuidle/current_driver"
#define CPU_IDLE_GOV_PATH       "/sys/devices/system/cpu/cpuidle/current_governor"
#define CPU_IDLE_AV_GOVS_PATH   "/sys/devices/system/cpu/cpuidle/available_governors"
#define CPU_IDLE_CSTATE_PATH    "/sys/devices/system/cpu/cpu0/cpuidle"
#define CPU_IDLE_CSTATE_DISALBE "/sys/devices/system/cpu/cpu0/cpuidle/%s/disable"
#define CPU_IDLE_CSTATE_LATENCY "/sys/devices/system/cpu/cpu0/cpuidle/%s/latency"
#define CPU_IDLE_CSTATE_NAME    "/sys/devices/system/cpu/cpu0/cpuidle/%s/name"

static int SupportCpuIdle(void)
{
    if (access(CPU_IDLE_CSTATE_PATH, F_OK) != 0) {
        return PWR_FALSE;
    }
    return PWR_TRUE;
}

static int ReadCpuIdleAvailableGovs(char govs[][PWR_MAX_ELEMENT_NAME_LEN], int maxGov)
{
    char content[MAX_LINE_LENGTH] = {0};
    int ret = ReadFile(CPU_IDLE_AV_GOVS_PATH, content, MAX_LINE_LENGTH);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    char *str = NULL;
    char *savePtr = NULL;
    int idx = 0;
    str = strtok_r(content, " ", &savePtr);
    while (str != NULL && idx < maxGov) {
        DeleteSubstr(str, " ");
        if (strlen(str) != 0) {
            StrCopy(govs[idx], str, PWR_MAX_ELEMENT_NAME_LEN);
            idx++;
        }
        str = strtok_r(NULL, " ", &savePtr);
    }
    return PWR_SUCCESS;
}

#define CPU_IDLE_CSTATE_DIR_FREFIX "state"
static int ReadCpuIdleCstates(PWR_CPU_Cstate cstates[], int *cstateNum, int maxNum)
{
    DIR *dir = opendir(CPU_IDLE_CSTATE_PATH);
    if (!dir) {
        Logger(ERROR, MD_NM_SVR_CPU, "Unable to open direct: %s", CPU_IDLE_CSTATE_PATH);
        return PWR_ERR_FILE_OPEN_FAILED;
    }

    int num = 0;
    struct dirent *dt;
    char path[MAX_FULL_NAME] = {0};
    char strInt[STR_LEN_FOR_INT] = {0};
    int ret = PWR_SUCCESS;
    while ((dt = readdir(dir)) != NULL && num < maxNum) {
        if (StrMatch(dt->d_name, CPU_IDLE_CSTATE_DIR_FREFIX) == NULL) {
            continue;
        }

        char dirName[PWR_MAX_ELEMENT_NAME_LEN] = {0};
        StrCopy(dirName, dt->d_name, PWR_MAX_ELEMENT_NAME_LEN);
        DeleteSubstr(dirName, CPU_IDLE_CSTATE_DIR_FREFIX);
        LRtrim(dirName);
        if (!IsNumStr(dirName)) {
            continue;
        }
        cstates[num].id = atoi(dirName);

        if (sprintf(path, CPU_IDLE_CSTATE_DISALBE, dt->d_name) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        ret = ReadIntFromFile(path, &cstates[num].disable);
        if (ret != PWR_SUCCESS) {
            return PWR_ERR_FILE_ACCESS_FAILED;
        }

        if (sprintf(path, CPU_IDLE_CSTATE_LATENCY, dt->d_name) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        ret = ReadIntFromFile(path, &cstates[num].latency);
        if (ret != PWR_SUCCESS) {
            return PWR_ERR_FILE_ACCESS_FAILED;
        }

        if (sprintf(path, CPU_IDLE_CSTATE_NAME, dt->d_name) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        ret = ReadFile(path, cstates[num].name, sizeof(cstates[num].name));
        if (ret != PWR_SUCCESS) {
            return PWR_ERR_FILE_ACCESS_FAILED;
        }
        num++;
    }
    *cstateNum = num;
    return PWR_SUCCESS;
}


static int ReadCpuIdleInfo(PWR_CPU_IdleInfo *idleInfo, int maxNum)
{
    int ret = PWR_SUCCESS;
    ret = ReadFile(CPU_IDLE_DRV_PATH, idleInfo->currDrv, sizeof(idleInfo->currDrv));
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    ret = ReadFile(CPU_IDLE_GOV_PATH, idleInfo->currGov, sizeof(idleInfo->currGov));
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    ret = ReadCpuIdleAvailableGovs(idleInfo->avGovs, PWR_MAX_IDLE_GOV_NUM);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    return ReadCpuIdleCstates(idleInfo->cstates, &idleInfo->cstateNum, maxNum);
}

// public===========================================================================================
void GetCpuinfo(PwrMsg *req)
{
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
    int coreNum = GetCpuCoreNumber();
    size_t size = sizeof(PWR_CPU_Usage) + sizeof(PWR_CPU_CoreUsage) * coreNum;
    PWR_CPU_Usage *rstData = malloc(size);
    if (!rstData) {
        return;
    }
    bzero(rstData, size);
    int rspCode = CPUUsageRead(rstData, coreNum);
    SendRspToClient(req, rspCode, (char *)rstData, size);
}

void GetCpuPerfData(PwrMsg *req)
{
    PWR_CPU_PerfData *rstData = malloc(sizeof(PWR_CPU_PerfData));
    if (!rstData) {
        return;
    }
    bzero(rstData, sizeof(PWR_CPU_PerfData));
    int rspCode = PerfDataRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_PerfData));
}

void GetCpuFreqGovernor(PwrMsg *req)
{
    char *rstData = malloc(PWR_MAX_ELEMENT_NAME_LEN);
    if (!rstData) {
        return;
    }
    bzero(rstData, PWR_MAX_ELEMENT_NAME_LEN);
    int rspCode = CurrentGovernorRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(char) * PWR_MAX_ELEMENT_NAME_LEN);
}

int SetGovernorForAllPcy(const char *gov)
{
    if (!gov) {
        return PWR_ERR_NULL_POINTER;
    }
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN] = {0};
    int poNum = 0;
    GetPolicys(policys, &poNum);
    return GovernorSet(gov, policys, &poNum);
}

void SetCpuFreqGovernor(PwrMsg *req)
{
    SendRspToClient(req, SetGovernorForAllPcy(req->data), NULL, 0);
}

void GetCpuFreqGovAttrs(PwrMsg *req)
{
    int rspCode = PWR_SUCCESS;
    PWR_CPU_FreqGovAttrs *rspData = (PWR_CPU_FreqGovAttrs *)malloc(sizeof(PWR_CPU_FreqGovAttrs));
    if (!rspData) {
        return;
    }
    bzero(rspData, sizeof(PWR_CPU_FreqGovAttrs));
    if (req->data == NULL || strlen(req->data) == 0) {
        CurrentGovernorRead(rspData->gov);
    } else {
        StrCopy(rspData->gov, req->data, PWR_MAX_ELEMENT_NAME_LEN);
    }
    rspCode = GetGovAttrs(rspData);
    if (rspCode != PWR_SUCCESS) {
        free(rspData);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)rspData, sizeof(PWR_CPU_FreqGovAttrs));
    }
}

void GetCpuFreqGovAttr(PwrMsg *req)
{
    int rspCode = PWR_SUCCESS;
    PWR_CPU_FreqGovAttr *attr = NULL;
    do {
        if (!req || req->head.dataLen != sizeof(PWR_CPU_FreqGovAttr)) {
            Logger(ERROR, MD_NM_SVR_CPU, "GetCpuFreqGovAttr: wrong req msg. dataLen:%d", req->head.dataLen);
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        attr = (PWR_CPU_FreqGovAttr *)req->data;
        if (strlen(attr->attr.key) == 0) {
            Logger(ERROR, MD_NM_SVR_CPU, "GetCpuFreqGovAttr: attr name is null");
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        if (strlen(attr->gov) == 0 && CurrentGovernorRead(attr->gov) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_CPU, "GetCpuFreqGovAttr: failed to find governor");
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        rspCode = GetGovAttr(attr);
    } while (PWR_FALSE);

    if (rspCode != PWR_SUCCESS) {
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        req->data = NULL;   // move the memory to rsp msg
        SendRspToClient(req, rspCode, (char *)attr, sizeof(PWR_CPU_FreqGovAttr));
    }
}

void SetCpuFreqGovAttr(PwrMsg *req)
{
    int rspCode = PWR_SUCCESS;
    PWR_CPU_FreqGovAttr *attr = NULL;
    do {
        if (!req || req->head.dataLen != sizeof(PWR_CPU_FreqGovAttr)) {
            Logger(ERROR, MD_NM_SVR_CPU, "SetCpuFreqGovAttr: wrong req msg. dataLen:%d", req->head.dataLen);
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        attr = (PWR_CPU_FreqGovAttr *)req->data;
        if (strlen(attr->attr.key) == 0) {
            Logger(ERROR, MD_NM_SVR_CPU, "SetCpuFreqGovAttr: attr name is null");
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        if (strlen(attr->gov) == 0 && CurrentGovernorRead(attr->gov) != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_CPU, "SetCpuFreqGovAttr: failed to find governor");
            rspCode = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        rspCode = SetGovAttr(attr);
    } while (PWR_FALSE);
    SendRspToClient(req, rspCode, NULL, 0);
}

void GetCpuFreq(PwrMsg *req)
{
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN] = {0};
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
    size_t num = (req->head.dataLen) / sizeof(PWR_CPU_CurFreq);
    char currentGov[PWR_MAX_ELEMENT_NAME_LEN] = {0};
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
    int coreNum = GetCpuCoreNumber();
    char policys[PWR_MAX_CPU_LIST_LEN][PWR_MAX_ELEMENT_NAME_LEN] = {0};
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
    PWR_CPU_FreqRange *rstData = malloc(sizeof(PWR_CPU_FreqRange));
    if (!rstData) {
        return;
    }
    bzero(rstData, sizeof(PWR_CPU_FreqRange));
    int rspCode = ScalingFreqRangeRead(rstData);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_FreqRange));
}

void SetCpuFreqRange(PwrMsg *req)
{
    PWR_CPU_FreqRange *rstData = (PWR_CPU_FreqRange *)req->data;

    int rspCode = FreqRangeSet(rstData);
    SendRspToClient(req, rspCode, NULL, 0);
}

// Total CPU cores
int GetCpuCoreNumber(void)
{
    return sysconf(_SC_NPROCESSORS_CONF);
}

void GetCpuIdleInfo(PwrMsg *req)
{
    if (!SupportCpuIdle()) {
        Logger(INFO, MD_NM_SVR_CPU, "The system does not support cpuidle.");
        SendRspToClient(req, PWR_ERR_NOT_SUPPORT_CPUIDLE, NULL, 0);
        return;
    }
    size_t size = sizeof(PWR_CPU_IdleInfo) + sizeof(PWR_CPU_Cstate) * PWR_MAX_CPU_CSTATE_NUM;
    PWR_CPU_IdleInfo *idleInfo = (PWR_CPU_IdleInfo *)malloc(size);
    if (!idleInfo) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(idleInfo, size);
    int rspCode = ReadCpuIdleInfo(idleInfo, PWR_MAX_CPU_CSTATE_NUM);
    if (rspCode != PWR_SUCCESS) {
        free(idleInfo);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)idleInfo, size);
    }
}

void GetCpuIdleGov(PwrMsg *req)
{
    if (!SupportCpuIdle()) {
        Logger(INFO, MD_NM_SVR_CPU, "The system does not support cpuidle.");
        SendRspToClient(req, PWR_ERR_NOT_SUPPORT_CPUIDLE, NULL, 0);
        return;
    }
    char *gov = (char *)malloc(PWR_MAX_ELEMENT_NAME_LEN);
    if (!gov) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    bzero(gov, PWR_MAX_ELEMENT_NAME_LEN);
    int rspCode = ReadFile(CPU_IDLE_GOV_PATH, gov, PWR_MAX_ELEMENT_NAME_LEN);
    if (rspCode != PWR_SUCCESS) {
        free(gov);
        SendRspToClient(req, rspCode, NULL, 0);
    } else {
        SendRspToClient(req, rspCode, (char *)gov, strlen(gov) + 1);
    }
}

void SetCpuIdleGov(PwrMsg *req)
{
    if (!SupportCpuIdle()) {
        Logger(INFO, MD_NM_SVR_CPU, "The system does not support cpuidle.");
        SendRspToClient(req, PWR_ERR_NOT_SUPPORT_CPUIDLE, NULL, 0);
        return;
    }
    if (req->head.dataLen == 0 || req->head.dataLen > PWR_MAX_ELEMENT_NAME_LEN || !req->data) {
        SendRspToClient(req, PWR_ERR_INVALIDE_PARAM, NULL, 0);
        return;
    }
    int rspCode = WriteFile(CPU_IDLE_GOV_PATH, (const char *)req->data, req->head.dataLen);
    SendRspToClient(req, rspCode, NULL, 0);
}

#define CPU_DMA_LANTENCY_PATH "/dev/cpu_dma_latency"
void GetCpuDmaLatency(PwrMsg *req)
{
    int *latency = (int *)malloc(sizeof(int));
    if (!latency) {
        SendRspToClient(req, PWR_ERR_SYS_EXCEPTION, NULL, 0);
        return;
    }
    *latency = 0;
    FILE *fd = fopen(CPU_DMA_LANTENCY_PATH, "rb");
    if (!fd) {
        SendRspToClient(req, PWR_ERR_FILE_ACCESS_FAILED, NULL, 0);
        return;
    }
    if (fread(latency, sizeof(int), 1, fd) < 0) {
        (void)fclose(fd);
        SendRspToClient(req, PWR_ERR_FILE_ACCESS_FAILED, NULL, 0);
        return;
    }
    (void)fclose(fd);
    SendRspToClient(req, PWR_SUCCESS, (char *)latency, sizeof(int));
}

static FILE *g_cpuDmaLatencyWriteFd = NULL;
void SetCpuDmaLatency(PwrMsg *req)
{
    int ret = PWR_SUCCESS;
    do {
        if (req->head.dataLen != sizeof(int) || !req->data) {
            ret = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        int *latency = (int *)req->data;

        if (*latency < 0 || *latency > PWR_MAX_CPU_DMA_LATENCY) {
            ret = PWR_ERR_INVALIDE_PARAM;
            break;
        }
        if (!g_cpuDmaLatencyWriteFd) {
            g_cpuDmaLatencyWriteFd = fopen(CPU_DMA_LANTENCY_PATH, "wb");
            if (!g_cpuDmaLatencyWriteFd) {
                ret = PWR_ERR_FILE_ACCESS_FAILED;
                break;
            }
        }

        if (fwrite(latency, sizeof(int), 1, g_cpuDmaLatencyWriteFd) < 0) {
            ret = PWR_ERR_FILE_ACCESS_FAILED;
            break;
        }
        (void)fflush(g_cpuDmaLatencyWriteFd);
        // It will set back to default value by the kernel after fd closed.
        // fclose(g_cpuDmaLatencyWriteFd);
    } while (PWR_FALSE);
    SendRspToClient(req, ret, NULL, 0);
}