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

TEST_F(RegisterOkCpuTest, PWR_CPU_GetFreq_Test_001)
{
    int coreNum = sysconf(_SC_NPROCESSORS_CONF);

    unsigned int len = coreNum;
    PWR_CPU_CurFreq *curFreq = (PWR_CPU_CurFreq *)malloc(coreNum * sizeof(PWR_CPU_CurFreq));
    EXPECT_EQ(SUCCESS, PWR_CPU_GetFreq(curFreq, &len, 0));
    EXPECT_EQ(coreNum, (int)len);
    for (unsigned int i = 0; i < len; i++) {
        EXPECT_LT(10, (unsigned int)curFreq[i].curFreq);
        printf("policyId:%d, freq:%lf\n", curFreq[i].policyId, curFreq[i].curFreq);
    }
}
