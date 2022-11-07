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
 * Description: PowerAPI testcase. All the cases in This file are based on testsuit RegisterOkTest
 * **************************************************************************** */
#include <gtest/gtest.h>
#include "GtestLog.h"
#include "powerapi.h"

#define MAIN_LOOP_INTERVAL 5
#define TEST_CORE_NUM 128

class RegisterOkTest : public ::testing::Test {
    protected:
        // 第一个个用例执行前被调用
        static void SetUpTestCase() {}
        // 最后一个用例执行完后调用
        static void TearDownTestCase() {}

        // 每个用例执行前调用
        virtual void SetUp()
        {
            PWR_SetLogCallback(LogCallback);
            while (PWR_Register() != SUCCESS) {
                sleep(MAIN_LOOP_INTERVAL);
                printf("main registed failed!\n");
                continue;
            }
            printf("main regist succeed.\n");
        }
        // 每个用例执行后调用
        virtual void TearDown()
        {
                PWR_UnRegister();
        }
};

TEST_F(RegisterOkTest, PWR_CPU_GetInfo_Test_001)
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

TEST_F(RegisterOkTest, PWR_CPU_GetUsage_Test_001)
{
    int ret;
    int buffSize = sizeof(PWR_CPU_Usage) + TEST_CORE_NUM * sizeof(PWR_CPU_CoreUsage);
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
    
