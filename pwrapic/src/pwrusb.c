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
 * Description: Provide service for PowerAPI refer to USB.
 * **************************************************************************** */

#include "pwrusb.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int GetUsbAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t *len)
{
    ReqInputParam input;
    input.optType = USB_GET_AUTO_SUSPEND;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    size_t s = sizeof(PWR_USB_AutoSuspend) * (*len);
    uint32_t size = s;
    output.rspBuffSize = &size;
    output.rspData = (void *)usbAts;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetUsbAutoSuspend failed. ret:%d", ret);
        size_t curLen = size / sizeof(PWR_USB_AutoSuspend);
        *len = curLen;
    } else {
        PwrLog(DEBUG, "GetUsbAutoSuspend Succeed.");
    }
    return ret;
}

int SetUsbAutoSuspend(PWR_USB_AutoSuspend usbAts[], uint32_t len)
{
    ReqInputParam input;
    input.optType = USB_SET_AUTO_SUSPEND;
    size_t dataLen = sizeof(PWR_USB_AutoSuspend) * len;
    input.dataLen = dataLen;
    input.data = (char *)usbAts;
    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetUsbAutoSuspend failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetUsbAutoSuspend Succeed.");
    }
    return ret;
}