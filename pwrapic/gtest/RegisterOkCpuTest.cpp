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
 * Author: jimmy-jiang-junior
 * Create: 2022-11-04
 * Description: PowerAPI testcase. All the cases in This file are based on testsuit RegisterOkCpuTest
 * **************************************************************************** */
#include <gtest/gtest.h>
#include "GtestLog.h"
#include "powerapi.h"
#include "Common.h"

#define TEST_CORE_NUM 128

class RegisterOkCpuTest : public ::testing::Test {
    protected:
        // 第一个个用例执行前被调用
        static void SetUpTestCase() {}
        // 最后一个用例执行完后调用
        static void TearDownTestCase() {}

        // 每个用例执行前调用
        virtual void SetUp()
        {
            EXPECT_EQ(0, StartService());
            EXPECT_EQ(SUCCESS, PWR_SetLogCallback(LogCallback));
            EXPECT_EQ(SUCCESS, PWR_Register());
            EXPECT_EQ(SUCCESS, PWR_RequestControlAuth());
        }
        // 每个用例执行后调用
        virtual void TearDown()
        {
            EXPECT_EQ(SUCCESS, PWR_ReleaseControlAuth());
            EXPECT_EQ(SUCCESS, PWR_UnRegister());
            EXPECT_EQ(0, StopService());
        }
};

TEST_F(RegisterOkCpuTest, PWR_SYS_GetRtPowerInfo_Test_001)
{
    PWR_SYS_PowerInfo powerInfo;
    EXPECT_EQ(SUCCESS, PWR_SYS_GetRtPowerInfo(&powerInfo));
    printf("sysPower:%02lf, cpuPower:%02lf, memPower:%02lf\n",
        powerInfo.sysPower, powerInfo.cpuPower, powerInfo.memPower);
    EXPECT_LT(0, powerInfo.sysPower);
}

TEST_F(RegisterOkCpuTest, PWR_SYS_GetRtPowerInfo_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_SYS_GetRtPowerInfo(NULL));
}

/*
 * 功能描述: PWR_CPU_GetInfo函数校验, 调动函数接口正常, 对函数的返回值做基本校验
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetInfo_Test_001)
{
    PWR_CPU_Info cpuInfo;
    EXPECT_EQ(SUCCESS, PWR_CPU_GetInfo(&cpuInfo));
    PWR_CPU_Info *info = &cpuInfo;
    printf("PWR_CPU_GetInfo arch:%s\n coreNum: %d\n maxFreq:%f\n minFreq:%f\n modelName: %s\n numaNum: %d\n "
        "threadsPerCore:%d\n", info->arch, info->coreNum, info->maxFreq, info->minFreq, info->modelName,
        info->numaNum, info->threadsPerCore);
    for (int i = 0; i < info->numaNum; i++) {
        printf("numa node %d  cpuList: %s\n", info->numa[i].nodeNo, info->numa[i].cpuList);
    }
    EXPECT_LT(0, info->coreNum);
    EXPECT_LT(10, info->minFreq);
    EXPECT_GT(20000, info->maxFreq);
    EXPECT_LT(info->minFreq, info->maxFreq);
    int modelNameLen = strlen(info->modelName);
    EXPECT_LT(2, modelNameLen);
    EXPECT_LT(0, info->numaNum);
    EXPECT_GT(info->coreNum + 1, info->numaNum);
    EXPECT_LT(0, info->threadsPerCore);
    for (int i = 0; i < info->numaNum; i++) {
        EXPECT_GT(info->numaNum, info->numa[i].nodeNo);
        int cpuListLen = strlen(info->numa[i].cpuList);
        EXPECT_LT(0, cpuListLen);
    }
}

TEST_F(RegisterOkCpuTest, PWR_CPU_GetInfo_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_GetInfo(NULL));
}

// 遗留问题, 需要写一段代码来添加负载, 然后检测CPU利用率
TEST_F(RegisterOkCpuTest, PWR_CPU_GetUsage_Test_001)
{
    int buffSize = sizeof(PWR_CPU_Usage) + TEST_CORE_NUM * sizeof(PWR_CPU_CoreUsage);
    PWR_CPU_Usage *usage = (PWR_CPU_Usage *)malloc(buffSize);
    EXPECT_FALSE(usage == NULL);
    EXPECT_EQ(SUCCESS, PWR_CPU_GetUsage(usage, buffSize));
    printf("PWR_CPU_GetUsage, CPU avgUsage:%f, coreNum: %d \n", usage->avgUsage, usage->coreNum);
    EXPECT_EQ(sysconf(_SC_NPROCESSORS_CONF), usage->coreNum);
    EXPECT_TRUE(!(usage->avgUsage < 0) && !(usage->avgUsage > 1));
    for (int i = 0; i < usage->coreNum; i++) {
        if (i > 0) {
            EXPECT_NE(usage->coreUsage[i].coreNo, usage->coreUsage[i - 1].coreNo);
        }
        EXPECT_TRUE(!(usage->coreUsage[i].usage < 0) && !(usage->coreUsage[i].usage > 1));
    }
    free(usage);
}

TEST_F(RegisterOkCpuTest, PWR_CPU_GetUsage_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_GetUsage(NULL, 1));
}

TEST_F(RegisterOkCpuTest, PWR_CPU_GetPerfData_Test_001)
{
    PWR_CPU_PerfData perfData;
    EXPECT_EQ(SUCCESS, PWR_CPU_GetPerfData(&perfData));
}

TEST_F(RegisterOkCpuTest, PWR_CPU_GetPerfData_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_GetPerfData(NULL));
}

/*
 * 功能描述：正常调用PWR_CPU_GetFreqAbility函数, 校验函数返回值
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreqAbility_Test_001)
{
    int coreNum = sysconf(_SC_NPROCESSORS_CONF);
    // 5: 用字符串表示CPU编号, 每个CPU最多占用5个字节, policyId占用4个字节
    int len = sizeof(PWR_CPU_FreqAbility) + (4 * 5) * coreNum;
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    EXPECT_TRUE(freqAbi != NULL);
    memset(freqAbi, 0, len);
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqAbility(freqAbi, len));
    printf("curDriver is %s\n", freqAbi->curDriver);
    printf("available governor is: \n");
    for (int i = 0; i < MAX_GOV_NUM; i++) {
        if (strlen(freqAbi->avGovList[i]) > 0) {
            printf("%s\n", freqAbi->avGovList[i]);
        }
    }
    EXPECT_TRUE((freqAbi->freqDomainNum <= coreNum) && (freqAbi->freqDomainNum > 0));
    printf("frequency domain num is: %d\n", freqAbi->freqDomainNum);
    EXPECT_LT(5, freqAbi->freqDomainStep);
    printf("frequency domain step is: %d\n", freqAbi->freqDomainStep);

    for (int i = 0; i < freqAbi->freqDomainNum; i++) {
        char *cpuList = &freqAbi->freqDomain[i * freqAbi->freqDomainStep + sizeof(int)];
        int policyId = int(freqAbi->freqDomain[i * freqAbi->freqDomainStep]);
        EXPECT_LT(0, strlen(cpuList)); // cpuList不为空
        if (coreNum == freqAbi->freqDomainNum) {
            if (policyId == 0) {
                EXPECT_EQ('0', cpuList[0]);
            } else {
                EXPECT_EQ(policyId, atoi(cpuList));
            }
        }
    }
    for (int i = 0; i < freqAbi->freqDomainNum; i++) {
        printf("domain index:%d cpulist:%s\n", int(freqAbi->freqDomain[i * freqAbi->freqDomainStep]),
            &freqAbi->freqDomain[i * freqAbi->freqDomainStep + sizeof(int)]);
    }
    free(freqAbi);
}

/*
 * 功能描述：函数PWR_CPU_GetFreqAbility函数入参为空
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreqAbility_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_GetFreqAbility(NULL, 0));
}

/*
 * 功能描述: 调用PWR_CPU_GetFreqRange获取CPU的频率范围,
 * 最小频率要大于10MHz, 最大频率不小最小频率
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreqRange_Test_001)
{
    PWR_CPU_FreqRange freqRange;
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqRange(&freqRange));
    EXPECT_LT(10, freqRange.maxFreq);
    EXPECT_TRUE(freqRange.minFreq <= freqRange.maxFreq);
}

TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreqRange_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_GetFreqRange(NULL));
}

/*
 * 功能描述: 调用PWR_CPU_SetFreqRange设置CPU频率
 * 调用函数PWR_CPU_GetFreqRange验证频率设置正确
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreqRange_Test_001)
{
    // governor设置为userspace
    char governor[] = "userspace";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(governor));
    char gov[MAX_ELEMENT_NAME_LEN] = {0};
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(governor, gov);

    PWR_CPU_Info cpuInfo;
    PWR_CPU_FreqRange freqRange;
    EXPECT_EQ(SUCCESS, PWR_CPU_GetInfo(&cpuInfo));
    freqRange.maxFreq = (cpuInfo.maxFreq < 2000) ? cpuInfo.maxFreq : 2000;
    freqRange.minFreq = (cpuInfo.minFreq > 1000) ? cpuInfo.minFreq : 1000;
    EXPECT_EQ(SUCCESS,  PWR_CPU_SetFreqRange(&freqRange));
    PWR_CPU_FreqRange actualFreqRange;
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqRange(&actualFreqRange));
    EXPECT_EQ(actualFreqRange.maxFreq, freqRange.maxFreq);
    EXPECT_EQ(actualFreqRange.minFreq, freqRange.minFreq);

    // 将最大频率恢复为硬件支持的最大频率
    freqRange.maxFreq = (int)cpuInfo.maxFreq;
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqRange(&freqRange));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqRange(&actualFreqRange));
    EXPECT_EQ(actualFreqRange.maxFreq, freqRange.maxFreq);

    // 将governor恢复为performance
    char govPerformance[] = "performance";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(govPerformance));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(govPerformance, gov);
}

TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreqRange_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_SetFreqRange(NULL));
}

/*
 * 功能描述: 调用PWR_CPU_SetFreqGovernor函数设置governor
 * 调用PWR_CPU_GetFreqGovernor函数校验设置是否成功
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreqGovernor_Test_001)
{
    char governor[] = "schedutil";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(governor));
    char gov[MAX_ELEMENT_NAME_LEN] = {0};
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(governor, gov);

    char govPerformance[] = "performance";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(govPerformance));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(govPerformance, gov);
}

/*
 * 功能描述: PWR_CPU_SetFreqGovernor函数的入参为NULL或者是错误的字符串, 应该返回错误
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreqGovernor_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_CPU_SetFreqGovernor(NULL));
    char gov[] = "fake";
    EXPECT_NE(SUCCESS, PWR_CPU_SetFreqGovernor(gov));
}

/*
 * 功能描述: PWR_CPU_GetFreqGovernor函数入参的存储空间大小不符合要求，应该返回错误
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreqGovernor_Test_001)
{
    char gov[3] = {0};
    EXPECT_NE(SUCCESS, PWR_CPU_GetFreqGovernor(gov, 3));
}

/*
 * 功能描述: 正常调用PWR_CPU_GetFreq函数, 应该返回正常, 且频率大于10MHz
 * 输入参数的数组长度比实际需要的长度大1, 检查返回的实际policy数目是否正常
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreq_Test_001)
{
    int coreNum = sysconf(_SC_NPROCESSORS_CONF);
    // 5: 用字符串表示CPU编号, 每个CPU最多占用5个字节, policyId占用4个字节
    int len = sizeof(PWR_CPU_FreqAbility) + (4 * 5) * coreNum;
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    EXPECT_TRUE(freqAbi != NULL);
    memset(freqAbi, 0, len);
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqAbility(freqAbi, len));

    unsigned int policyNum = (unsigned int)freqAbi->freqDomainNum + 1;
    PWR_CPU_CurFreq *curFreq = (PWR_CPU_CurFreq *)calloc(policyNum, sizeof(PWR_CPU_CurFreq));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreq(curFreq, &policyNum, 0));
    EXPECT_EQ(policyNum, freqAbi->freqDomainNum);
    for (unsigned int i = 0; i < policyNum; i++) {
        EXPECT_LT(10, (unsigned int)curFreq[i].curFreq);
        printf("policyId:%d, freq:%lf\n", curFreq[i].policyId, curFreq[i].curFreq);
    }
    free(freqAbi);
    free(curFreq);
}

/*
 * 功能描述: 正常调用PWR_CPU_GetFreq函数, 应该返回正常, 且频率大于10MHz
 * 第三个参数设置为1
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreq_Test_002)
{
    int coreNum = sysconf(_SC_NPROCESSORS_CONF);
    // 5: 用字符串表示CPU编号, 每个CPU最多占用5个字节, policyId占用4个字节
    int len = sizeof(PWR_CPU_FreqAbility) + (sizeof(int) * 5) * coreNum;
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    EXPECT_TRUE(freqAbi != NULL);
    memset(freqAbi, 0, len);
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqAbility(freqAbi, len));

    unsigned int policyNum = (unsigned int)freqAbi->freqDomainNum + 1;
    PWR_CPU_CurFreq *curFreq = (PWR_CPU_CurFreq *)calloc(policyNum, sizeof(PWR_CPU_CurFreq));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreq(curFreq, &policyNum, 1));
    EXPECT_EQ(policyNum, freqAbi->freqDomainNum);
    for (unsigned int i = 0; i < policyNum; i++) {
        // 10: 获取到的频率至少要大于10MHz
        EXPECT_LT(10, (unsigned int)curFreq[i].curFreq);
        printf("policyId:%d, freq:%lf\n", curFreq[i].policyId, curFreq[i].curFreq);
    }
    free(freqAbi);
    free(curFreq);
}

/*
 * 功能描述: PWR_CPU_GetFreq函数入参为NULL, 应该返回错误
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreq_Test_003)
{
    EXPECT_NE(SUCCESS, PWR_CPU_GetFreq(NULL, 0, 0));
}

/*
 * 功能描述: 将governor设置为userspace, 并调用PWR_CPU_SetFreq设置频率
 * 当cpufreq driver为cppc_cpufreq时, 调用PWR_CPU_GetFreq检查频率设置是否正确
 * 将governor恢复为performance
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreq_Test_001)
{
    int coreNum = sysconf(_SC_NPROCESSORS_CONF);
    // 5: 用字符串表示CPU编号, 每个CPU最多占用5个字节, policyId占用4个字节
    int len = sizeof(PWR_CPU_FreqAbility) + (sizeof(int) * 5) * coreNum;
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    EXPECT_TRUE(freqAbi != NULL);
    memset(freqAbi, 0, len);
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqAbility(freqAbi, len));

    // governor设置为userspace
    char governor[] = "userspace";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(governor));
    char gov[MAX_ELEMENT_NAME_LEN] = {0};
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(governor, gov);

    // 将每个policy的频率都设置为2000MHz, 并调用函数PWR_CPU_GetFreq检查设置成功
    unsigned int policyNum = (unsigned int)freqAbi->freqDomainNum;
    PWR_CPU_CurFreq *curFreq = (PWR_CPU_CurFreq *)calloc(policyNum, sizeof(PWR_CPU_CurFreq));
    for (unsigned int i = 0; i < policyNum; i++) {
        curFreq[i].policyId = (int)freqAbi->freqDomain[i * freqAbi->freqDomainStep];
        curFreq[i].curFreq = 2000.0;
    }
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreq(curFreq, policyNum));
    if (std::string(freqAbi->curDriver) == std::string("cppc_cpufreq")) {
        printf("check frequency, if cpufreq driver is cppc_cpufreq\n");
        EXPECT_EQ(SUCCESS, PWR_CPU_GetFreq(curFreq, &policyNum, 0));
        for (unsigned int i = 0; i < policyNum; i++) {
            EXPECT_EQ(2000, (int)curFreq[i].curFreq);
        }
    }

    // governor恢复为performance
    char govPerformance[] = "performance";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(govPerformance));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(govPerformance, gov);

    free(curFreq);
    free(freqAbi);
}

/*
 * 功能描述: 将governor设置为performance, 并调用PWR_CPU_SetFreq设置频率
 * 此时应该返回正常
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreq_Test_002)
{
    int coreNum = sysconf(_SC_NPROCESSORS_CONF);
    // 5: 用字符串表示CPU编号, 每个CPU最多占用5个字节, policyId占用4个字节
    int len = sizeof(PWR_CPU_FreqAbility) + (4 * 5) * coreNum;
    PWR_CPU_FreqAbility *freqAbi = (PWR_CPU_FreqAbility *)malloc(len);
    EXPECT_TRUE(freqAbi != NULL);
    memset(freqAbi, 0, len);
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqAbility(freqAbi, len));

    // governor设置为performance
    char govPerformance[] = "performance";
    EXPECT_EQ(SUCCESS, PWR_CPU_SetFreqGovernor(govPerformance));
    char gov[MAX_ELEMENT_NAME_LEN] = {0};
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreqGovernor(gov, MAX_ELEMENT_NAME_LEN));
    EXPECT_STREQ(govPerformance, gov);

    unsigned int policyNum = (unsigned int)freqAbi->freqDomainNum;
    PWR_CPU_CurFreq *curFreq = (PWR_CPU_CurFreq *)calloc(policyNum, sizeof(PWR_CPU_CurFreq));
    for (unsigned int i = 0; i < policyNum; i++) {
        curFreq[i].policyId = int(freqAbi->freqDomain[i * freqAbi->freqDomainStep]);
        curFreq[i].curFreq = 2000.0;
    }
    EXPECT_NE(SUCCESS, PWR_CPU_SetFreq(curFreq, policyNum));

    free(curFreq);
    free(freqAbi);
}

/*
 * 功能描述: 函数PWR_CPU_SetFreq为空指针, 应该返回错误
 */
TEST_F(RegisterOkCpuTest, PWR_CPU_SetFreq_Test_003)
{
    EXPECT_NE(SUCCESS, PWR_CPU_SetFreq(NULL, 0));
}