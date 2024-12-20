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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include "common.h"
#include "config.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"
#include "cpuservice.h"
#include "pwrdata.h"

#define PWR_SLICE_SIZE 40
enum PWR_Arch {
    PWR_AARCH_64 = 0,
    PWR_X86_64 = 1,
};

enum PWR_CpuAttType {
    PWR_ARCH = 0,
    PWR_MODEL_NAME,
    PWR_BYTE_OR,
    PWR_NUMA_NUMBER,
    PWR_NUMA_NODE,
    PWR_CPU_NUMBER,
    PWR_ONLINE_CPU,
    PWR_THREADS_PER_CORE,
    PWR_CORES_PER_SOCKET,
    PWR_MAX_MHZ,
    PWR_MIN_MHZ,
};

static const char cpuAttributes[PWR_MAX_ARRRIBUTES][PWR_MAX_NAME_LEN] = {
    "Architecture", "Model name", "Byte Order", "NUMA node(s)", "NUMA node", "CPU(s)",
    "On-line CPU", "Thread(s) per core", "Core(s) per socket", "max MHz", "min MHz"
};

static int GetCpuArrId(const char *att)
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
    // Bubble Sort
    int i, j;
    PWR_CPU_CurFreq temp;
    int exchanged = PWR_FALSE;
    for (i = 0; i < len; i++) {
        for (j = 0; j < len - i - 1; j++) {
            if (rstData[j].policyId > rstData[j + 1].policyId) {
                temp = rstData[j + 1];
                rstData[j + 1] = rstData[j];
                rstData[j] = temp;
                exchanged = PWR_TRUE;
            }
        }
        if (exchanged) {
            exchanged = PWR_FALSE;
        } else {
            break;
        }
    }
}

static void CpuInfoCopy(char *att, char *value, PWR_CPU_Info *rstData)
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
            if (j < PWR_MAX_NUMA_NODE_NUM) {
                rstData->numa[j].nodeNo = j;
                StrCopy(rstData->numa[j].cpuList, value, PWR_MAX_CPU_LIST_LEN);
            }
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

static int GetArch(void)
{
    static int arch = -1;
    if (arch != -1) {
        return arch;
    }
    struct utsname utsn = {0};
    if(uname(&utsn) != 0) {
        return -1;
    }
    if (strstr(utsn.machine, "aarch64") != NULL) {
        arch = PWR_AARCH_64;
    } else if (strstr(utsn.machine, "x86_64") != NULL) {
        arch = PWR_X86_64;
    }
    return arch;
}

static int UsageToLong(char *buf, unsigned long paras[], int line)
{
    int i = 0;
    int j = 0;
    int k;
    char temp[PWR_MAX_STRING_LEN];
    while (i < PWR_CPU_USAGE_COLUMN) {
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
    unsigned long cacheMiss = 0;
    unsigned long ins = 0;
    unsigned long cycles = 0;
    while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
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
    fclose(fp);
    remove("perf.txt");
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
    while ((*poNum) < PWR_MAX_CPUFREQ_POLICY_NUM && (ent = readdir(dir)) != NULL) {
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
    int cpuNum = sysconf(_SC_NPROCESSORS_CONF);
    int *isIdVisited = (int *)malloc(cpuNum * sizeof(int));
    if (isIdVisited == NULL) {
        return;
    }
    memset(isIdVisited, 0, sizeof(int) * cpuNum);
    int count = 0;
    int policyId = 0;
    for (int i = 0; i < *len; i++) {
        policyId = target[i].policyId;
        if (policyId < cpuNum && isIdVisited[policyId] == 0) {
            isIdVisited[policyId] = 1;
            target[count].policyId = policyId;
            count++;
        }
    }

    *len = count;
    free(isIdVisited);
}

/**
 * CheckPolicys - check if the target policy is valid
*/
static int CheckPolicys(const PWR_CPU_CurFreq *target, int num)
{
    const char patten[] = "/sys/devices/system/cpu/cpufreq/policy%d";
    char path[PWR_MAX_STRING_LEN] = {0};
    for (int i = 0; i < num; i++) {
        if (sprintf(path, patten, target[i].policyId) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }
        if (access(path, F_OK) != 0) {
            return PWR_ERR_INVALIDE_PARAM;
        }
    }
    return PWR_SUCCESS;
}

static int IsPolicyAffectedCpuOffline(const int policyId)
{
    char affectedCpuPath[PWR_MAX_STRING_LEN] = {0};
    char fileContent[PWR_MAX_STRING_LEN] = {0};
    const char *policyPathPattern = "/sys/devices/system/cpu/cpufreq/policy%d/affected_cpus";

    if (snprintf(affectedCpuPath, PWR_MAX_STRING_LEN - 1, policyPathPattern,
                 policyId) < 0) {
        Logger(ERROR, MD_NM_SVR_CPU, "Failed to snprintf affectedCpuPath");
        return PWR_FALSE;
    }

    int ret = ReadFile(affectedCpuPath, fileContent, PWR_MAX_STRING_LEN);

    return (ret == 1 || strlen(fileContent) == 0);
}

/*
 * Read the value of the specified attribute file of the specified policy
 */
static int FreqPolicyFileRead(const char *policy, const char* attrFile, char *value, int len)
{
    char path[PWR_MAX_NAME_LEN] = {0};
    const char* pathPattern = "/sys/devices/system/cpu/cpufreq/%s/%s";

    if (snprintf(path, PWR_MAX_NAME_LEN - 1, pathPattern, policy, attrFile) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    int ret = ReadFile(path, value, len);
    if (ret != PWR_SUCCESS || strlen(value) == 0) {
        // check if the afftected cpus of  policy is offline
        int tmpPolicyId = atoi(policy + strlen("policy"));
        if (IsPolicyAffectedCpuOffline(tmpPolicyId)) {
            Logger(
                WARNING, MD_NM_SVR_CPU, "policy %d related cpu is offline, skip it", tmpPolicyId);
            ret = PWR_ERR_CPU_OFFLINE;
        }
    }
    return ret;
}

static int FreqPolicyFileWrite(const char *policy, const char* attrFile, const char *value)
{
    char path[PWR_MAX_NAME_LEN] = {0};
    const char* pathPattern = "/sys/devices/system/cpu/cpufreq/%s/%s";

    if (snprintf(path, PWR_MAX_NAME_LEN - 1, pathPattern, policy, attrFile) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    int ret = WriteFile(path, value, strlen(value));
    if (ret != PWR_SUCCESS) {
        // check if the afftected cpus of policy is offline
        int tmpPolicyId = atoi(policy + strlen("policy"));
        if (IsPolicyAffectedCpuOffline(tmpPolicyId)) {
            Logger(
                WARNING, MD_NM_SVR_CPU, "policy %d related cpu is offline, skip it", tmpPolicyId);
            ret = PWR_ERR_CPU_OFFLINE;
        }
    }
    return ret;
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

static int CheckAvailableGovernor(const char *gov, const char *policys)
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

static int ReadGovernorByPolicy(char *gov, const char *pcy)
{
    const char base[] = "/sys/devices/system/cpu/cpufreq/%s/scaling_governor";
    char path[PWR_MAX_STRING_LEN] = {0};
    if(sprintf(path, base, pcy) < 0){
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }
    int ret = ReadFile(path, gov, PWR_MAX_ELEMENT_NAME_LEN);
    LRtrim(gov);
    return ret;
}

static int GovernorSet(const char *gov, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int *poNum)
{
    int i;
    for (i = 0; i < (*poNum); i++) {
        if (CheckAvailableGovernor(gov, policys[i]) != 0) {
            return PWR_ERR_GOVERNOR_INVALIDE;
        }
    }

    int hasSuccess = PWR_FALSE;
    int ret = PWR_SUCCESS;
    for (i = 0; i < (*poNum); i++) {
        ret = FreqPolicyFileWrite(policys[i], "scaling_governor", gov);
        if (ret == PWR_ERR_CPU_OFFLINE) {
            continue;
        }
        if (ret != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_SVR_CPU, "change %s gov(%s) failed.", policys[i], gov);
            break;
        }
        hasSuccess = PWR_TRUE;
    }
    return (hasSuccess == PWR_TRUE) ? PWR_SUCCESS : ret;
}

typedef struct FreqReadInfo {
    int startIdx;
    int endIdx;
    const char *patten;
    char (*policys)[PWR_MAX_ELEMENT_NAME_LEN];
    PWR_CPU_CurFreq *rstData;   // out
    int result; // out
} FreqReadInfo;

static void *RunFreqReadProcess(void *arg)
{
    FreqReadInfo *info = (FreqReadInfo*)arg;
    info->result = PWR_SUCCESS;
    char path[PWR_MAX_STRING_LEN] = {0};
    char buf[PWR_MAX_STRING_LEN] = {0};
    int hasSuccess = PWR_FALSE;
    for (int i = info->startIdx; i <= info->endIdx; i++) {
        bzero(buf, PWR_MAX_STRING_LEN);
        if (sprintf(path, info->patten, info->policys[i]) < 0) {
            info->result = PWR_ERR_FILE_SPRINTF_FAILED;
            return &(info->result);
        }
        info->result = ReadFile(path, buf, PWR_MAX_STRING_LEN);
        if (info->result != PWR_SUCCESS || strlen(buf) == 0 || strcmp(buf, "<unknown>") == 0) {
            int policyId = atoi((char*)(info->policys[i]) + strlen("policy"));
            if (IsPolicyAffectedCpuOffline(policyId)) {
                Logger(WARNING, MD_NM_SVR_CPU, "policy %d is offline", policyId);
                info->rstData[i].policyId = policyId;
                info->rstData[i].curFreq  = 0;
                info->result = (hasSuccess == PWR_TRUE) ? PWR_SUCCESS : PWR_ERR_CPU_OFFLINE;
                continue;
            }
            return &(info->result);
        } else {
            hasSuccess = PWR_TRUE;
        }

        DeleteChar(buf, ' ');
        DeleteSubstr(info->policys[i], "policy");
        info->rstData[i].policyId = atoi(info->policys[i]);
        info->rstData[i].curFreq = (double)strtoul(buf, NULL, PWR_DECIMAL) / PWR_CONVERSION;
    }
    return &(info->result);
}

static int MutiThreadFreqRead(PWR_CPU_CurFreq *rstData, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN],
    int poNum, const char *patten)
{
    Logger(DEBUG, MD_NM_SVR_CPU, "multi thread for freqread poNum:%d", poNum);
    int tNum = (poNum % PWR_SLICE_SIZE == 0) ? poNum / PWR_SLICE_SIZE : poNum / PWR_SLICE_SIZE + 1;
    FreqReadInfo info[tNum];
    pthread_t tids[tNum];
    bzero(info, sizeof(FreqReadInfo) * tNum);
    bzero(tids, sizeof(pthread_t) * tNum);
    int ret = PWR_SUCCESS;
    int s;
    for (s = 0; s < tNum; s++) {
        info[s].patten = patten;
        info[s].policys = policys;
        info[s].rstData = rstData;
        info[s].startIdx = s * PWR_SLICE_SIZE;
        int end = info[s].startIdx + PWR_SLICE_SIZE - 1;
        info[s].endIdx = end < poNum ? end : poNum - 1;
        if (pthread_create(&tids[s], NULL, RunFreqReadProcess, (void*)&info[s]) != 0) {
            ret = PWR_ERR_SYS_EXCEPTION;
            Logger(ERROR, MD_NM_SVR_CPU, "create thread for freqread failed. %d", s);
            break;
        }
    }
    if (ret != PWR_SUCCESS) {
        for (int i = 0; i < s; i++) {
            pthread_join(tids[i], NULL);
        }
        return ret;
    }
    int hasSuccess = PWR_FALSE;
    for (int i = 0; i < tNum; i++) {
        // waiting for all threads to the end.
        if (pthread_join(tids[i], NULL) == 0 && info[i].result == PWR_SUCCESS) {
            hasSuccess = PWR_TRUE;
            continue;
        } else {
            ret = info[i].result;
            continue;
        }
    }
    ret = ((hasSuccess == PWR_TRUE) ? PWR_SUCCESS : ret);
    return ret;
}

/**
 * FreqRead - get target policy freq based on the given policys
 * @policys: target policys
 * @poNum:   valid policys num
*/
static int FreqRead(PWR_CPU_CurFreq *rstData, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int poNum)
{
    int m = GetArch();
    int ret = -1;
    int hasSuccess = PWR_FALSE;
    const char s2Arm[] = "/sys/devices/system/cpu/cpufreq/%s/cpuinfo_cur_freq";
    const char s2X86[] = "/sys/devices/system/cpu/cpufreq/%s/scaling_cur_freq";
    const char *patten = NULL;
    if (m == PWR_AARCH_64) {
        patten = s2Arm;
    } else if (m == PWR_X86_64) {
        patten = s2X86;
    } else {
        return PWR_ERR_SYS_EXCEPTION;
    }
    if (poNum > PWR_SLICE_SIZE) {
        // use multi thread to accelerate the processing.
        ret = MutiThreadFreqRead(rstData, policys, poNum, patten);
        if (ret != PWR_SUCCESS) {
            return ret;
        }
    } else {
        char path[PWR_MAX_STRING_LEN] = {0};
        char buf[PWR_MAX_STRING_LEN] = {0};
        for (int i = 0; i < poNum; i++) {
            bzero(buf, PWR_MAX_STRING_LEN);
            if (sprintf(path, patten, policys[i]) < 0) {
                return PWR_ERR_FILE_SPRINTF_FAILED;
            }
            ret = ReadFile(path, buf, PWR_MAX_STRING_LEN);
            if (ret != PWR_SUCCESS || strlen(buf) == 0 || strcmp(buf, "<unknown>") == 0) {
                int policyId = atoi(policys[i] + strlen("policy"));
                if (IsPolicyAffectedCpuOffline(policyId)) {
                    Logger(WARNING, MD_NM_SVR_CPU, "policy %d is offline", policyId);
                    rstData[i].policyId = policyId;
                    rstData[i].curFreq = 0;
                    // One policy read freq success, return success
                    ret = (hasSuccess == PWR_TRUE) ? PWR_SUCCESS : PWR_ERR_CPU_OFFLINE;
                    continue;
                }
                return ret;
            } else {
                hasSuccess = PWR_TRUE;
            }

            rstData[i].policyId = atoi((char*)(policys[i]) + strlen("policy"));
            DeleteChar(buf, ' ');
            rstData[i].curFreq = (double)strtoul(buf, NULL, PWR_DECIMAL) / PWR_CONVERSION;
        }
    }

    FreqSortByPolicy(rstData, poNum);
    return ret;
}

static int FreqSet(PWR_CPU_CurFreq *target, int num)
{
    char setFreqPath[PWR_MAX_NAME_LEN] = {0};
    const char *setFreqPathPattern = "/sys/devices/system/cpu/cpufreq/policy%d/scaling_setspeed";
    int i, freq;
    int ret = -1;
    int hasSuccess = PWR_FALSE;
    char freqValStr[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    for (i = 0; i < num; i++) {
        // Get string of freq value.
        freq = (int)target[i].curFreq * THOUSAND;
        if (snprintf(freqValStr, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", freq) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }

        // Get string of scaling_setspeed path.
        if (snprintf(setFreqPath, PWR_MAX_NAME_LEN - 1, setFreqPathPattern, target[i].policyId) < 0) {
            return PWR_ERR_FILE_SPRINTF_FAILED;
        }

        ret = WriteFile(setFreqPath, freqValStr, strlen(freqValStr));
        if (ret != PWR_SUCCESS) {
            if (IsPolicyAffectedCpuOffline(target[i].policyId)) {
                Logger(WARNING, MD_NM_SVR_CPU,
                       "policy %d related cpu is offline, skip it",
                       target[i].policyId);
                //  One policy is written successfully, return success.
                ret = (hasSuccess == PWR_TRUE) ? PWR_SUCCESS : PWR_ERR_CPU_OFFLINE;
                continue;
            }
            return ret;
        } else {
            hasSuccess = PWR_TRUE;
        }
    }
    return ret;
}

static int FreqDriverRead(char *buf, int bufLen)
{
    const char driverInfo[] = "/sys/devices/system/cpu/cpufreq/policy0/scaling_driver";
    return ReadFile(driverInfo, buf, bufLen);
}

static int FreqDomainRead(char *buf, char (*policys)[PWR_MAX_ELEMENT_NAME_LEN], int domainNum, int step)
{
    char domainbuf[PWR_MAX_CPU_LIST_LEN] = {0};
    int *pcyId = NULL;
    for (int i = 0; i < domainNum; i++) {
        bzero(domainbuf, PWR_MAX_CPU_LIST_LEN);

        int ret = FreqPolicyFileRead(policys[i], "affected_cpus", domainbuf, PWR_MAX_CPU_LIST_LEN);
        if (ret == PWR_ERR_CPU_OFFLINE || ret == PWR_SUCCESS) {
            pcyId = (int*)(buf + i * step);
            *pcyId = atoi((char*)(policys[i]) + strlen("policy"));
            StrCopy(buf + i * step + sizeof(int), domainbuf, step - sizeof(int));
        } else {
            break;
        }
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
    char policys[PWR_MAX_CPUFREQ_POLICY_NUM][PWR_MAX_ELEMENT_NAME_LEN] = {0};
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
    if (rstData->minFreq < cpuFreqRange.minFreq || rstData->maxFreq > cpuFreqRange.maxFreq) {
        Logger(ERROR,MD_NM_SVR_CPU,
               "cpu freq range: [%d, %d]. the input minfreq[%d] "
               "or maxfreq[%d] is invalide",
               cpuFreqRange.minFreq,
               cpuFreqRange.maxFreq,
               rstData->minFreq,
               rstData->maxFreq);
        return PWR_ERR_FREQ_NOT_IN_RANGE;
    }

    // set min freq
    if (snprintf(buf, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->minFreq * THOUSAND) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    for (i = 0; i < poNum; i++) {
        ret = FreqPolicyFileWrite(policys[i], "scaling_min_freq", buf);
        if (ret != PWR_SUCCESS && ret != PWR_ERR_CPU_OFFLINE) {
            Logger(ERROR, MD_NM_SVR_CPU, "set policy%d min freq to %d failed", i, rstData->minFreq);
            return ret;
        }
    }

    // set max freq
    bzero(buf, PWR_MAX_ELEMENT_NAME_LEN);
    if (snprintf(buf, PWR_MAX_ELEMENT_NAME_LEN - 1, "%d", rstData->maxFreq * THOUSAND) < 0) {
        return PWR_ERR_FILE_SPRINTF_FAILED;
    }

    for (i = 0; i < poNum; i++) {
        ret = FreqPolicyFileWrite(policys[i], "scaling_max_freq", buf);
        if (ret != PWR_SUCCESS && ret != PWR_ERR_CPU_OFFLINE) {
            Logger(ERROR, MD_NM_SVR_CPU, "set policy%d max freq to %d failed", i, rstData->minFreq);
            return ret;
        }
    }

    return PWR_SUCCESS;
}

static int GovIsActive(const char *gov)
{
    char policys[PWR_MAX_CPUFREQ_POLICY_NUM][PWR_MAX_ELEMENT_NAME_LEN] = {0};
    int poNum = 0;
    GetPolicys(policys, &poNum);

    if (CheckAvailableGovernor(gov, policys[0]) != 0) {
        return PWR_ERR_GOVERNOR_INVALIDE;
    }

    char pcyGov[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    for (int i = 0; i < poNum; i++) {
        bzero(pcyGov, PWR_MAX_ELEMENT_NAME_LEN);
        (void)ReadGovernorByPolicy(pcyGov, policys[i]);
        if (strcmp(gov, pcyGov) == 0) {
            return PWR_SUCCESS;
        }
    }
    return PWR_ERR_GOVERNOR_INACTIVE;
}

static int GetGovAttrs(PWR_CPU_FreqGovAttrs *attrs)
{
    char base[] = "/sys/devices/system/cpu/cpufreq/";
    char attrPath[PWR_MAX_NAME_LEN] = {0};
    StrCopy(attrPath, base, PWR_MAX_NAME_LEN - 1);
    strcat(attrPath, attrs->gov);
    DIR *dir = opendir(attrPath);
    if (dir == NULL) {
        Logger(WARNING, MD_NM_SVR_CPU, "This gov does not have attrs: %s", attrPath);
        return PWR_SUCCESS;
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
        StrCopy(pathEnd, dt->d_name, PWR_MAX_ELEMENT_NAME_LEN);
        ret = ReadFile(attrPath, attrs->attrs[attrs->attrNum].value, PWR_MAX_VALUE_LEN);
        if (ret != PWR_SUCCESS) {
            continue;
        }
        StrCopy(attrs->attrs[attrs->attrNum].key, dt->d_name, PWR_MAX_ELEMENT_NAME_LEN);
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
    if (access(attrPath, F_OK) != 0) {
        return PWR_ERR_ATTR_NOT_EXISTS;
    }
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
    if (access(attrPath, F_OK) != 0) {
        return PWR_ERR_ATTR_NOT_EXISTS;
    }
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
        ret = ReadIntFromFile(path, (int *)&cstates[num].latency);
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
    return ReadCpuIdleCstates(idleInfo->cstates, (int *)&idleInfo->cstateNum, maxNum);
}

// public===========================================================================================
void GetCpuinfo(PwrMsg *req)
{
    PWR_CPU_Info *rstData = malloc(sizeof(PWR_CPU_Info));
    if (!rstData) {
        return;
    }
    bzero(rstData, sizeof(PWR_CPU_Info));
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
    char policys[PWR_MAX_CPUFREQ_POLICY_NUM][PWR_MAX_ELEMENT_NAME_LEN] = {0};
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
        rspCode = GovIsActive(rspData->gov);
        if (rspCode != PWR_SUCCESS) {
            free(rspData);
            SendRspToClient(req, rspCode, NULL, 0);
            return;
        }
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

        if (strlen(attr->gov) == 0) {
            if (CurrentGovernorRead(attr->gov) != PWR_SUCCESS) {
                Logger(ERROR, MD_NM_SVR_CPU, "GetCpuFreqGovAttr: failed to find governor");
                rspCode = PWR_ERR_INVALIDE_PARAM;
                break;
            }
        } else {
            rspCode = GovIsActive(attr->gov);
            if (rspCode != PWR_SUCCESS) {
                break;
            }
        }
        bzero(attr->attr.value, sizeof(attr->attr.value));
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
        if (strlen(attr->gov) == 0) {
            if (CurrentGovernorRead(attr->gov) != PWR_SUCCESS) {
                Logger(ERROR, MD_NM_SVR_CPU, "SetCpuFreqGovAttr: failed to find governor");
                rspCode = PWR_ERR_INVALIDE_PARAM;
                break;
            }
        } else {
            rspCode = GovIsActive(attr->gov);
            if (rspCode != PWR_SUCCESS) {
                break;
            }
        }
        rspCode = SetGovAttr(attr);
    } while (PWR_FALSE);
    SendRspToClient(req, rspCode, NULL, 0);
}

void GetCpuFreq(PwrMsg *req)
{
    // policy strings, like this, {"policy0", "policy1", ...}
    char policys[PWR_MAX_CPUFREQ_POLICY_NUM][PWR_MAX_ELEMENT_NAME_LEN] = {0};
    int poNum;
    int rspCode = 0;

    // spec = 1, get cpu frequency of specific policys
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
        // spec = 0, get cpu frequency  of all policys
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
    rspCode = FreqRead(rstData, policys, poNum);
    SendRspToClient(req, rspCode, (char *)rstData, sizeof(PWR_CPU_CurFreq) * poNum);
}

#define GOV_USERSPACE "userspace"
void SetCpuFreq(PwrMsg *req)
{
    size_t num = (req->head.dataLen) / sizeof(PWR_CPU_CurFreq);
    char currentGov[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    PWR_CPU_CurFreq *target = (PWR_CPU_CurFreq *)req->data;

    // check whether current governor is userspace
    int ret = CurrentGovernorRead(currentGov);
    if (ret != PWR_SUCCESS) {
        SendRspToClient(req, ret, NULL, 0);
        return;
    }
    if (strcmp(currentGov, GOV_USERSPACE) != 0) {
        SendRspToClient(req, PWR_ERR_GOVERNOR_INVALIDE, NULL, 0);
        return;
    }

    if (CheckPolicys(target, num) == 1) {
        SendRspToClient(req, PWR_ERR_POLICY_INVALIDE, NULL, 0);
        return;
    }

    // check whether frequency is in range
    PWR_CPU_FreqRange freqRange;
    ret = ScalingFreqRangeRead(&freqRange);
    if (ret != 0) {
        SendRspToClient(req, ret, NULL, 0);
        return;
    }
    if (CheckFreqInRange(target, num, freqRange) != 0) {
        SendRspToClient(req, PWR_ERR_FREQ_NOT_IN_RANGE, NULL, 0);
        return;
    }

    SendRspToClient(req, FreqSet(target, num), NULL, 0);
}

void GetCpuFreqAbility(PwrMsg *req)
{
    int coreNum = GetCpuCoreNumber();
    char policys[PWR_MAX_CPUFREQ_POLICY_NUM][PWR_MAX_ELEMENT_NAME_LEN] = {0};
    int poNum;
    if (GetPolicys(policys, &poNum) != PWR_SUCCESS) {
        int rspCode = PWR_ERR_COMMON;
        SendRspToClient(req, rspCode, NULL, 0);
        return;
    }
    // how many bytes taken by each policy's freq domain
    // freq domain is a char array, has two part "pocliyId {cpu cores} "
    // e.g "0 0 1 2 3 4 5 6 7 " -> policy0 has 8 cores(0-7)
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
    if (fread(latency, sizeof(int), 1, fd) == 0) {
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

        if (fwrite(latency, sizeof(int), 1, g_cpuDmaLatencyWriteFd) == 0) {
            ret = PWR_ERR_FILE_ACCESS_FAILED;
            break;
        }
        (void)fflush(g_cpuDmaLatencyWriteFd);
        // It will set back to default value by the kernel after fd closed.
        // fclose(g_cpuDmaLatencyWriteFd);
    } while (PWR_FALSE);
    SendRspToClient(req, ret, NULL, 0);
}