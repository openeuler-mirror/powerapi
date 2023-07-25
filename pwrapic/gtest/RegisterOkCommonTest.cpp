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
 * Description: PowerAPI testcase. All the cases in This file are based on testsuit RegisterOkTestCommon
 * **************************************************************************** */
#include <ctime>
#include <string>
#include <gtest/gtest.h>
#include "GtestLog.h"
#include "powerapi.h"
#include "Common.h"

#define TEST_CORE_NUM 128
#define AVG_LEN_PER_CORE 5
#define TASK_INTERNAL 1000

class RegisterOkTestCommon : public ::testing::Test {
    protected:
        // 第一个个用例执行前被调用
        static void SetUpTestCase() {}
        // 最后一个用例执行完后调用
        static void TearDownTestCase() {}

        // 每个用例执行前调用
        virtual void SetUp()
        {
            EXPECT_EQ(0, StartService());
            EXPECT_EQ(0, PWR_SetLogCallback(LogCallback));
            EXPECT_EQ(0, PWR_Register());
        }
        // 每个用例执行后调用
        virtual void TearDown()
        {
            EXPECT_EQ(0, PWR_UnRegister());
            EXPECT_EQ(0, StopService());
        }
};

/*
 * 功能描述: 没有调用PWR_SetMetaDataCallbak注册回调函数, 直接创建回调一个任务, 返回失败
 */
TEST_F(RegisterOkTestCommon, PWR_CreateDcTask_Test_001)
{
    PWR_COM_BasicDcTaskInfo task = {};
    task.dataType = PWR_COM_DATATYPE_CPU_PERF;
    task.interval = TASK_INTERNAL;
    EXPECT_NE(PWR_SUCCESS, PWR_CreateDcTask(&task));
}

/*
 * 功能描述: 注册两个回调任务, 校验注册函数和删除函数工作正常
 */
TEST_F(RegisterOkTestCommon, PWR_DeleteDcTask_Test_001)
{
    int ret = PWR_SUCCESS;
    EXPECT_EQ(PWR_SUCCESS, PWR_SetMetaDataCallback(MetaDataCallback));

    PWR_COM_BasicDcTaskInfo task = {};
    task.dataType = PWR_COM_DATATYPE_CPU_PERF;
    task.interval = TASK_INTERNAL;
    EXPECT_EQ(PWR_SUCCESS, PWR_CreateDcTask(&task));
    printf("PWR_CreateDcTask. dataType:%d ret: %d\n", task.dataType, ret);
    task.dataType = PWR_COM_DATATYPE_CPU_USAGE;
    EXPECT_EQ(PWR_SUCCESS, PWR_CreateDcTask(&task));
    printf("PWR_CreateDcTask. dataType:%d ret: %d\n", task.dataType, ret);

    sleep(3);
    EXPECT_EQ(PWR_SUCCESS, PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_PERF));
    printf("PWR_DeleteDcTask. dataType:%d ret: %d\n", PWR_COM_DATATYPE_CPU_PERF, ret);
    EXPECT_EQ(PWR_SUCCESS, PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_USAGE));
    printf("PWR_DeleteDcTask. dataType:%d ret: %d\n", PWR_COM_DATATYPE_CPU_USAGE, ret);
}

/*
 * 功能描述: PWR_SetMetaDataCallbak任务入参为NULL, 返回失败
 */
TEST_F(RegisterOkTestCommon, PWR_SetMetaDataCallback_Test_001)
{
    EXPECT_NE(PWR_SUCCESS, PWR_SetMetaDataCallback(NULL));
}

/*
 * 功能描述: 通过lamda函数创建回调函数, 注册回调任务获取ipc和llcMiss
 * 在回调函数中对ipc和llcMiss做大于0的校验
 */
TEST_F(RegisterOkTestCommon, PWR_SetMetaDataCallback_Test_002)
{
    EXPECT_EQ(PWR_SUCCESS,
        PWR_SetMetaDataCallback([](const PWR_COM_CallbackData *callbackData) {
            EXPECT_EQ(PWR_COM_DATATYPE_CPU_PERF, callbackData->dataType);
            PWR_CPU_PerfData *perfData = (PWR_CPU_PerfData *)(callbackData->data);
            EXPECT_LT(0, perfData->ipc);
            EXPECT_LT(0, perfData->llcMiss);

            time_t curTime;
            tm *nowTime;
            time(&curTime); // 获取1970到目前经过秒数
            nowTime = localtime(&curTime); // 输出tm结构的年月日

            int year = 1900 + nowTime->tm_year;
            int month = 1 + nowTime->tm_mon;
            int day = nowTime->tm_mday;
            std::string str = callbackData->ctime;
            EXPECT_NE(std::string::npos, str.find(std::to_string(year)));
            EXPECT_NE(std::string::npos, str.find(std::to_string(month)));
            EXPECT_NE(std::string::npos, str.find(std::to_string(day)));
            printf("[TASK]Get PERF data. ipc: %f  miss: %f, ctime:%s\n", perfData->ipc, perfData->llcMiss,
                callbackData->ctime);
        }));

    PWR_COM_BasicDcTaskInfo task = {};
    task.dataType = PWR_COM_DATATYPE_CPU_PERF;
    task.interval = TASK_INTERNAL;
    EXPECT_EQ(PWR_SUCCESS, PWR_CreateDcTask(&task));
    sleep(3);
    EXPECT_EQ(PWR_SUCCESS, PWR_DeleteDcTask(PWR_COM_DATATYPE_CPU_PERF));
}

/*
 * 功能描述: 由于没有权限, 所有的SET操作都会失败, 所有的Get操作都可以成功
 */
TEST_F(RegisterOkTestCommon, PWR_RequestControlAuth_Test_001)
{
    PWR_CPU_Info cpuInfo;
    EXPECT_EQ(PWR_SUCCESS, PWR_CPU_GetInfo(&cpuInfo));

    int buffSize = sizeof(PWR_CPU_Usage) + TEST_CORE_NUM * sizeof(PWR_CPU_CoreUsage);
    PWR_CPU_Usage *u = (PWR_CPU_Usage *)malloc(buffSize);
    EXPECT_FALSE(u == NULL);
    EXPECT_EQ(PWR_SUCCESS, PWR_CPU_GetUsage(u, buffSize));
    free(u);

    PWR_CPU_PerfData perfData;
    EXPECT_EQ(PWR_SUCCESS, PWR_CPU_GetPerfData(&perfData));

    char gov[PWR_MAX_ELEMENT_NAME_LEN] = {0};
    EXPECT_EQ(PWR_SUCCESS, PWR_CPU_GetFreqGovernor(gov, PWR_MAX_ELEMENT_NAME_LEN));

    uint32_t len = TEST_CORE_NUM;
    PWR_CPU_CurFreq curFreq[len];
    int spec = 0;
    EXPECT_EQ(PWR_SUCCESS, PWR_CPU_GetFreq(curFreq, &len, spec));

    EXPECT_NE(PWR_SUCCESS, PWR_SYS_SetPowerState(1));

    char governor[] = "performance";
    EXPECT_NE(PWR_SUCCESS, PWR_CPU_SetFreqGovernor(governor));
}

/*
 * 功能描述: PWR_RequestControlAuth()接口校验
 * 获取权限后调用Set类接口成功, 释放接口后调用Set类接口失败
 */
TEST_F(RegisterOkTestCommon, PWR_ReleaseControlAuth_Test_001)
{
    char governor[] = "performance";
    EXPECT_EQ(PWR_SUCCESS, PWR_RequestControlAuth());
    EXPECT_EQ(PWR_SUCCESS, PWR_RequestControlAuth());
    EXPECT_EQ(PWR_SUCCESS, PWR_CPU_SetFreqGovernor(governor));
    EXPECT_EQ(PWR_SUCCESS, PWR_ReleaseControlAuth());
    EXPECT_NE(PWR_SUCCESS, PWR_CPU_SetFreqGovernor(governor));
}