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

TEST(GTEST_BASE, case_001)
{
    printf("This the Gtest Base\n");
}

TEST(GTEST_BASE, PWR_SetLogCallback_Test_001)
{
    EXPECT_EQ(SUCCESS, PWR_SetLogCallback(LogCallback));
}

TEST(GTEST_BASE, PWR_SetLogCallback_Test_002)
{
    EXPECT_NE(SUCCESS, PWR_SetLogCallback(NULL));
}
