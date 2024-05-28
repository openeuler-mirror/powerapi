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
 * Create: 2022-11-01
 * Description: Provide service for PowerAPI refer to TASK.
 * **************************************************************************** */

#include "pwrtask.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int CreateDcTask(const PWR_COM_BasicDcTaskInfo *basicDcTaskInfo)
{
    ReqInputParam input;
    input.optType = COM_CREATE_DC_TASK;
    size_t dataLen = sizeof(PWR_COM_BasicDcTaskInfo);
    input.dataLen = dataLen;
    input.data = (char *)basicDcTaskInfo;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "CreateDcTask failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "CreateDcTask succeed.");
    }
    return ret;
}

int DeleteDcTask(PWR_COM_COL_DATATYPE dataType)
{
    ReqInputParam input;
    input.optType = COM_DELETE_DC_TASK;
    size_t dataLen = sizeof(dataType);
    input.dataLen = dataLen;
    input.data = (char *)&dataType;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "DeleteDcTask failed. ret: %d", ret);
    } else {
        PwrLog(DEBUG, "DeleteDcTask succeed.");
    }
    return ret;
}