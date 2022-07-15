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
 * Description: Provide service for PowerAPI refer to CPU.
 * **************************************************************************** */

#include "pwrcpu.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "pwrmsg.h"
#include "sockclient.h"

int GetUsage(CPUUsage *usage)
{
    if (!usage) {
        return ERR_NULL_POINTER;
    }
    // 组装消息
    PwrMsg *msg = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!msg) {
        PwrLog(ERROR, "malloc failed.");
        return ERR_COMMON;
    }
    bzero(msg, sizeof(PwrMsg));
    if (GenerateReqMsg(msg, GET_CPU_USAGE, 0, 0, NULL) != SUCCESS) {
        PwrLog(ERROR, "Generate GetUsage req msg failed.");
        ReleasePwrMsg(&msg);
        return ERR_COMMON;
    }

    // 发送消息
    PwrMsg *rsp = NULL;
    if (SendMsgSyn(msg, &rsp) != SUCCESS) {
        PwrLog(ERROR, "send GET_CPU_USAGE msg failed.");
        ReleasePwrMsg(&msg);
        ReleasePwrMsg(&rsp);
        return ERR_COMMON;
    }

    if (rsp == NULL || rsp->head.rspCode != SUCCESS) {
        ReleasePwrMsg(&msg);
        ReleasePwrMsg(&rsp);
        return rsp == NULL ? ERR_COMMON : rsp->head.rspCode;
    }

    // 填充结果
    if (rsp->data) {
        usage->usage = ((CPUUsage *)(rsp->data))->usage;
    } else {
        usage->usage = 0;
    }

    PwrLog(DEBUG, "GET_CPU_USAGE succeed.");
    ReleasePwrMsg(&msg);
    ReleasePwrMsg(&rsp);
    return SUCCESS;
}
