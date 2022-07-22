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
 * Description: provide cpu service
 * **************************************************************************** */

#include "cpuservice.h"
#include "string.h"
#include "pwrerr.h"
#include "server.h"
#include "pwrdata.h"
#include "log.h"


void GetCpuUsage(PwrMsg *req)
{
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_CPU, "Get GetCpuUsage Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    int rspCode = SUCCESS;
    PWR_CPU_Usage *rstData = malloc(sizeof(PWR_CPU_Usage));
    if (!rstData) {
        return;
    }
    rstData->avgUsage = 40; // todo 调用适配层能力获取CPU使用率
    rstData->coreNum = 0;

    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_CPU, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(PWR_CPU_Usage));
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}
