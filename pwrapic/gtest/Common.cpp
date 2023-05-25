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
 * Create: 2022-11-24
 * Description: Common functions for powerAPI gtest
 * **************************************************************************** */
#include <cstdio>
#include <string>
#include <unistd.h>
#include <gtest/gtest.h>
#include "Common.h"

int StartService(void)
{
    char dir[4096] = {0};
    int ret = readlink("/proc/self/exe", dir, 4096);
    if (ret < 0) {
        printf("readlink ret:%d\n", ret);
        return -1;
    }

    std::string gtestDir = dir;
    std::string pwrapisDir;
    // 10: length for "gtest_test", keep only the path of file
    gtestDir = gtestDir.substr(0, gtestDir.length() - 10);
    pwrapisDir = gtestDir + "../pwrapis/pwrapis &";
    ret = system(pwrapisDir.c_str());
    if (ret != 0) {
        printf("StartService failed ret:%d\n", ret);
        return -1;
    }
    sleep(1);

    return 0;
}


int StopService(void)
{
    int ret = system("ps -elf | grep pwrapis | grep -v grep | awk '{print $4}' | xargs kill");
    if (ret != 0) {
        printf("StopSerive failed ret:%d\n", ret);
        return -1;
    }
    sleep(1);

    return 0;
}

void MetaDataCallback(const PWR_COM_CallbackData *callbackData)
{
    PWR_CPU_PerfData *perfData = NULL;
    PWR_CPU_Usage *usage = NULL;
    switch (callbackData->dataType) {
        case PWR_COM_DATATYPE_CPU_PERF:
            perfData = (PWR_CPU_PerfData *)(callbackData->data);
            printf("[TASK]Get PERF data. ipc: %f  miss: %f, ctime:%s\n", perfData->ipc, perfData->llcMiss,
                callbackData->ctime);
            break;
        case PWR_COM_DATATYPE_CPU_USAGE:
            usage = (PWR_CPU_Usage *)(callbackData->data);
            printf("[TASK]Get Cpu Usage. avgUsage: %f, coreNum:%d, ctime:%s\n", usage->avgUsage, usage->coreNum,
                callbackData->ctime);
            EXPECT_TRUE(!(usage->avgUsage < 0) && !(usage->avgUsage > 1));
            for (int i = 0; i < usage->coreNum; i++) {
                if (i > 0) {
                    EXPECT_NE(usage->coreUsage[i].coreNo, usage->coreUsage[i - 1].coreNo);
                }
                EXPECT_TRUE(!(usage->coreUsage[i].usage < 0) && !(usage->coreUsage[i].usage > 1));
            }
            break;
        default:
            printf("[TASK]Get INVALIDE data.\n");
            break;
    }
}

void EventCallback(const PWR_COM_EventInfo *eventInfo)
{
    printf("[Event] Get event notification\n");
    switch (eventInfo->eventType) {
        case PWR_COM_EVTTYPE_CRED_FAILED:
            printf("[Event] ctime:%s, type:%d\n", eventInfo->ctime, eventInfo->eventType);
            printf("[Event] info:%s\n", eventInfo->info);
            break;
        default:
            printf("[Event] Get invalid event.\n");
            break;
    }
}