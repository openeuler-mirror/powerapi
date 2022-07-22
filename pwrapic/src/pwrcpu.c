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

int GetCpuInfo(PWR_CPU_Info *cpuInfo)
{
    PwrMsg *req = CreateReqMsg(CPU_GET_INFO, 0, 0, NULL);
    if (!req) {
        PwrLog(ERROR, "Create CPU_GET_INFO req msg failed.");
        return ERR_SYS_EXCEPTION;
    }

    PwrMsg *rsp = NULL;
    int ret = SendReqAndWaitForRsp(req, &rsp);
    if (ret != SUCCESS || !(rsp->data) || rsp->head.dataLen != sizeof(PWR_CPU_Info)) {
        PwrLog(ERROR, "CPU_GET_INFO req failed. ret:%d", ret);
        ReleasePwrMsg(&req);
        ReleasePwrMsg(&rsp);
        return ret == SUCCESS ? ERR_COMMON : ret;
    }

    memcpy(cpuInfo, rsp->data, sizeof(PWR_CPU_Info));
    PwrLog(DEBUG, "CPU_GET_INFO Succeed.");
    ReleasePwrMsg(&req);
    ReleasePwrMsg(&rsp);
    return SUCCESS;
}

int GetCpuUsage(PWR_CPU_Usage *usage, uint32_t bufferSize)
{
    // 组装消息
    PwrMsg *req = CreateReqMsg(CPU_GET_USAGE, 0, 0, NULL);
    if (!req) {
        PwrLog(ERROR, "Create CPU_GET_USAGE req msg failed.");
        return ERR_SYS_EXCEPTION;
    }

    // 发送消息
    PwrMsg *rsp = NULL;
    int ret = SendReqAndWaitForRsp(req, &rsp);
    if (ret != SUCCESS || !(rsp->data) || rsp->head.dataLen < sizeof(PWR_CPU_Usage)) {
        PwrLog(ERROR, "CPU_GET_USAGE req failed. ret:%d", ret);
        ReleasePwrMsg(&req);
        ReleasePwrMsg(&rsp);
        return ret == SUCCESS ? ERR_COMMON : ret;
    }

    // 填充结果
    int dlen = rsp->head.dataLen < bufferSize ? rsp->head.dataLen : bufferSize;
    memcpy(usage, rsp->data, dlen);
    usage->coreNum = (dlen - sizeof(PWR_CPU_Usage)) / sizeof(PWR_CPU_CoreUsage);

    PwrLog(DEBUG, "GET_CPU_USAGE succeed.");
    ReleasePwrMsg(&req);
    ReleasePwrMsg(&rsp);
    return SUCCESS;
}
