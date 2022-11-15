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
 * Author: wuhaotian
 * Create: 2022-11-10
 * Description: provide cpu service
 * **************************************************************************** */

#include "cpuservice.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "log.h"
#include "unistd.h"
#include "utils.h"

int PowerSet(char *powerState)
{
    FILE *fp = NULL;
    char *stateStr = malloc(strlen(powerState) + MAX_NAME_LEN);
    if (stateStr == NULL) {
        Logger(ERROR, MD_NM_SVR_SYS, "Malloc failed.");
        return 1;
    }
    static const char s1[] = "sleep 10 && echo ";
    static const char s2[] = "> /sys/power/state &";
    StrCopy(stateStr, s1, strlen(powerState) + MAX_NAME_LEN);
    strncat(stateStr, powerState, strlen(powerState));
    strncat(stateStr, s2, strlen(s2));
    fp = popen(stateStr, "r");
    if (fp == NULL) {
        return 1;
    }
    pclose(fp);
    return SUCCESS;
}

void SetSysPowerState(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_SYS, "Set Sys Power State Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    int rspCode = PowerSet(req->data);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_SYS, "Malloc failed.");
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, NULL, 0);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}
