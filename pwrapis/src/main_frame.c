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
#include "pwrerr.h"

#define ARGS_NUM 2
#define MAIN_LOOP_INTERVAL 5
static int g_keepMainRunning;

static void PrintUsage(const char *args[])
{
    printf("Usage: %s < config_file_name > \n", args[0]);
}

static int BaseInit(void)
{
    int ret = PWR_SUCCESS;
    ret = InitConfig();
    if (ret != PWR_SUCCESS) {
        return ret;
    }

    ret = InitLogger();
    if (ret != PWR_SUCCESS) {
        return ret;
    }

    return PWR_SUCCESS;
}

static void ClearEnv(void)
{
    // todo：必要的环境清理动作
    ClearLogger();
}

static void SignalHandler(int none)
{
    (void)none; // used to avoid unused parameter warning
    g_keepMainRunning = EXIT;
}

static void SetupSignal(void)
{
    // regist signal handler
    (void)signal(SIGINT, SignalHandler);
    (void)signal(SIGUSR1, SignalHandler);
    (void)signal(SIGUSR2, SignalHandler);
    (void)signal(SIGTERM, SignalHandler);
    (void)signal(SIGKILL, SignalHandler);
    (void)signal(SIGPIPE, SIG_IGN);
}

int main(int argc, const char *args[])
{
    int ret;
    if (argc < ARGS_NUM) {
        PrintUsage(args);
    } else {
        ret = UpdateConfigPath(args[1]);
        if (ret != PWR_SUCCESS) {
            Logger(ERROR, MD_NM_MAN, "Update config path failed. ret:%d", ret);
            exit(-1);
        }
    }

    ret = BaseInit();
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_MAN, "BaseInit failed. ret:%d", ret);
        exit(-1);
    }

    ret = StartServer();
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_MAN, "Start Server failed. ret:%d", ret);
        exit(-1);
    }
    Logger(INFO, MD_NM_MAN, "Start Server succeed.");

    SetupSignal();
    g_keepMainRunning = KEEP_RUN;
    while (g_keepMainRunning) {
        sleep(MAIN_LOOP_INTERVAL);
        CheckAndUpdateConfig();
    }
    StopServer();
    ClearEnv();
    return 0;
}
