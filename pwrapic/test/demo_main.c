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
 * Description: PowerAPI DEMO for testing the interface.
 * **************************************************************************** */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "powerapi.h"

static int g_run = 1;

static const char *GetLevelName(int level)
{
    static char debug[] = "DEBUG";
    static char info[] = "INFO";
    static char warning[] = "WARNING";
    static char error[] = "ERROR";
    switch (level) {
        case 0:
            return debug;
        case 1:
            return info;
        case 2:
            return warning;
        case 3:
            return error;
        default:
            return info;
    }
}

void LogCallback(int level, const char *fmt, va_list vl)
{
    char logLine[4096] = {0};
    char message[4000] = {0};

    if (vsnprintf(message, sizeof(message) - 1, fmt, vl) < 0) {
        return;
    }

    printf("%s: %s\n", GetLevelName(level), message);
}

static void SignalHandler()
{
    g_run = 0;
}

static void SetupSignal()
{
    // regist signal handler
    signal(SIGINT, SignalHandler);
    signal(SIGUSR1, SignalHandler);
    signal(SIGUSR2, SignalHandler);
    signal(SIGTERM, SignalHandler);
    signal(SIGKILL, SignalHandler);
}

int main(int argc, const char *args[])
{
    PWR_SetLogCallback(LogCallback);
    while (PWR_Register() != SUCCESS) {
        sleep(3);
        printf("main registed failed!\n");
        continue;
    }
    printf("main regist succeed.\n");

    int ret = 0;

    // PWR_CPU_GetUsage
    int buffSize = sizeof(PWR_CPU_Usage) + 128 * sizeof(PWR_CPU_CoreUsage);
    PWR_CPU_Usage *u = (PWR_CPU_Usage *)malloc(buffSize);
    bzero(u, buffSize);
    ret = PWR_CPU_GetUsage(u, buffSize);
    printf("ret: %d, CPU avgUsage:%f, coreNum: %d \n", ret, u->avgUsage, u->coreNum);
    for (int i = 0; i < u->coreNum; i++) {
        printf("core%d usage: %f\n", u->coreUsage[i].coreNo, u->coreUsage[i].usage);
    }
    free(u);


    // todo: 其他接口测试

    while (g_run) {
        sleep(5);
    }
    PWR_UnRegister();
    return 0;
}