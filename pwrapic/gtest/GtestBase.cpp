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
 * Description: The simplest testcase for PowrAPI based on gtest
 * **************************************************************************** */
#include <gtest/gtest.h>
#include "GtestLog.h"
#include "powerapi.h"
#include "Common.h"

TEST(GTEST_BASE, PWR_SetLogCallback_Test_001)
{
    EXPECT_EQ(PWR_SUCCESS, PWR_SetLogCallback(LogCallback));
}

TEST(GTEST_BASE, PWR_SetLogCallback_Test_002)
{
    EXPECT_NE(PWR_SUCCESS, PWR_SetLogCallback(NULL));
}

/*
 * 功能描述: 先拉起Service, 然后调用PWR_Register应该返回成功
 */
TEST(GTEST_BASE, PWR_Register_Test_001)
{
    EXPECT_EQ(0, StartService());
    EXPECT_EQ(PWR_SUCCESS, PWR_Register());
    EXPECT_EQ(PWR_SUCCESS, PWR_UnRegister());
    EXPECT_EQ(0, StopService());
}

/*
 * 功能描述: 不拉起Serive, 然后调用PWR_Register应该返回失败
 */
TEST(GTEST_BASE, PWR_Register_Test_002)
{
    EXPECT_NE(PWR_SUCCESS, PWR_Register());
}

/*
 * 功能描述: 不调用Register, 直接调用UnRegister应该成功
 */
TEST(GTEST_BASE, PWR_UnRegister_Test_001)
{
    EXPECT_EQ(PWR_SUCCESS, PWR_UnRegister());
}

/*
 * 功能描述: 先Stop Service, 然后执行UnRegister, 返回成功
 */
TEST(GTEST_BASE, PWR_UnRegister_Test_002)
{
    EXPECT_EQ(0, StartService());
    EXPECT_EQ(PWR_SUCCESS, PWR_Register());
    EXPECT_EQ(0, StopService());
    EXPECT_EQ(PWR_SUCCESS, PWR_UnRegister());
}

/*
 * 连续Register和UnRegister, 应该返回成功
 */
TEST(GTEST_BASE, PWR_UnRegister_Test_003)
{
    EXPECT_EQ(0, StartService());
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(PWR_SUCCESS, PWR_Register());
        EXPECT_EQ(PWR_SUCCESS, PWR_UnRegister());
    }
    EXPECT_EQ(0, StopService());
}

/*
 * 功能描述: 连续Register, 应该返回成功
 */
TEST(GTEST_BASE, PWR_UnRegister_Test_004)
{
    EXPECT_EQ(0, StartService());
    EXPECT_EQ(PWR_SUCCESS, PWR_Register());
    EXPECT_EQ(PWR_SUCCESS, PWR_Register());
    EXPECT_EQ(PWR_SUCCESS, PWR_UnRegister());
    EXPECT_EQ(0, StopService());
}

