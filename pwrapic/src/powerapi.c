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
 * Author: queyanwen
 * Create: 2022-06-23
 * Description: PowerAPI interface implementation.
 * **************************************************************************** */

#include "powerapi.h"
#include <stdio.h>
#include "pwrlog.h"
#include "sockclient.h"
#include "pwrcpu.h"

static int g_registed = 0;

#define CHECK_STATUS                    \
    if (!g_registed) {                  \
        PwrLog(ERROR, "Not Registed."); \
        return ERR_NOT_REGISTED;        \
    }

static void DefaultLogCallback(int level, const char *fmt, va_list vl)
{
    printf(fmt);
}

void (*PwrLogCallback)(int level, const char *fmt, va_list vl) = DefaultLogCallback;

int PWR_SetLogCallback(void(LogCallback)(int, const char *, va_list))
{
    if (LogCallback) {
        PwrLogCallback = LogCallback;
        return 0;
    }
    return -1;
}

int PWR_Register()
{
    // todo: 增加必要的其他初始化动作
    if (InitSockClient() != SUCCESS) {
        return ERR_COMMON;
    }
    g_registed = 1;
    return SUCCESS;
}

int PWR_UnRegister()
{
    CHECK_STATUS
    int ret = FiniSockClient();
    // todo: 增加必要的其他去初始化动作
    g_registed = 0;
    return ret;
}

int PWR_CPU_GetUsage(CPUUsage *usage)
{
    CHECK_STATUS
    if (!usage) {
        return ERR_NULL_POINTER;
    }
    int ret = GetUsage(usage);
    return ret;
}
