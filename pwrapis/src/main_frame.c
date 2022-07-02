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
 * Description: initialize and app enter
 * **************************************************************************** */
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "server.h"
#include "config.h"
#include "log.h"

#define ARGS_NUM 2
static int g_keepMainRunning;

static void PrintUsage(const char *args[])
{
    printf("Usage: %s < config_file_name > \n", args[0]);
}

static int BaseInit()
{
    int ret = SUCCESS;
    ret = InitConfig();
    if (ret != SUCCESS) {
        return ret;
    }

    ret = InitLogger();
    if (ret != SUCCESS) {
        return ret;
    }

    // todo 其他必要的初始化
    return SUCCESS;
}

static void ClearEnv()
{
    // todo：必要的环境清理动作
    ClearLogger();
}

static void SignalHandler()
{
    g_keepMainRunning = EXIT;
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
    int ret;
    /* if (argc < ARGS_NUM) {
        PrintUsage(args);
        return -1;
    } */ // todo 增加启动参数，比如指定配置文件路径

    ret = BaseInit();
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_MAN, "BaseInit failed. ret:%d", ret);
        exit(-1);
    }

    ret = StartServer();
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_MAN, "Start Server failed. ret:%d", ret);
        exit(-1);
    }
    Logger(INFO, MD_NM_MAN, "Start Server succeed.");

    SetupSignal();
    g_keepMainRunning = KEEP_RUN;
    while (g_keepMainRunning) {
        sleep(5);
        CheckAndUpdateConfig();
        // todo 系统定时任务(比如配置文件更新)触发
    }
    StopServer();
    ClearEnv();
    return 0;
}
