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
 * Create: 2022-11-15
 * Description: Provide service for PowerAPI refer to common function.
 * **************************************************************************** */

#include "pwrcom.h"
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int RequestControlAuth(void)
{
    ReqInputParam input;
    input.optType = COM_REQUEST_CONTROL_AUTH;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != SUCCESS) {
        PwrLog(ERROR, "RequestControlAuth failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "RequestControlAuth Succeed.");
    }
    return ret;
}

int ReleaseControlAuth(void)
{
    ReqInputParam input;
    input.optType = COM_RELEASE_CONTROL_AUTH;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != SUCCESS) {
        PwrLog(ERROR, "ReleaseControlAuth failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "ReleaseControlAuth Succeed.");
    }
    return ret;
}
