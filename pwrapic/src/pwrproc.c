/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: queyanwen
 * Create: 2023-10-19
 * Description: Provide service for PowerAPI refer to process function.
 * **************************************************************************** */

#include "pwrproc.h"
#include <string.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "sockclient.h"

int QueryProcsByKeywords(const char *keywords, pid_t procs[], uint32_t *num)
{
    ReqInputParam input;
    input.optType = PROC_QUERY_PROCS;
    input.dataLen = strlen(keywords) + 1;
    input.data = (char *)keywords;

    RspOutputParam output;
    uint32_t size = (uint32_t)sizeof(pid_t) * (*num);
    output.rspBuffSize = &size;
    output.rspData = (char *)procs;

    int ret = SendReqAndWaitForRsp(input, output);
    *num = (uint32_t)(size / sizeof(pid_t));
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "QueryProcsByKeywords failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "QueryProcsByKeywords succeed.");
    }
    return ret;
}

int GetProcWattState(int *state)
{
    ReqInputParam input;
    input.optType = PROC_GET_WATT_STATE;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    uint32_t size = (uint32_t)sizeof(int);
    output.rspBuffSize = &size;
    output.rspData = (char *)state;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetProcWattState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetProcWattState succeed.");
    }
    return ret;
}

int SetProcWattState(int state)
{
    ReqInputParam input;
    input.optType = PROC_SET_WATT_STATE;
    input.dataLen = (uint32_t)sizeof(state);
    input.data = (char *)&state;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetProcWattState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetProcWattState succeed.");
    }
    return ret;
}

int SetWattFirstDomain(int cpuId)
{
    ReqInputParam input;
    input.optType = PROC_SET_WATT_FIRST_DOMAIN;
    input.dataLen = (uint32_t)sizeof(cpuId);
    input.data = (char *)&cpuId;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetWattFirstDomain failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetWattFirstDomain succeed.");
    }
    return ret;
}

int GetProcWattAttrs(PWR_PROC_WattAttrs *wattAttrs)
{
    ReqInputParam input;
    input.optType = PROC_GET_WATT_ARRTS;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    uint32_t size = (uint32_t)sizeof(PWR_PROC_WattAttrs);
    output.rspBuffSize = &size;
    output.rspData = (char *)wattAttrs;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetProcWattState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetProcWattState succeed.");
    }
    return ret;
}

int SetProcWattAttrs(const PWR_PROC_WattAttrs *wattAttrs)
{
    ReqInputParam input;
    input.optType = PROC_SET_WATT_ARRTS;
    uint32_t size = (uint32_t)sizeof(PWR_PROC_WattAttrs);
    input.dataLen = size;
    input.data = (char *)wattAttrs;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetProcWattAttrs failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetProcWattAttrs succeed.");
    }
    return ret;
}

int GetWattProcs(pid_t wattProcs[], uint32_t *num)
{
    ReqInputParam input;
    input.optType = PROC_GET_WATT_PROCS;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    uint32_t size = (uint32_t)sizeof(pid_t) * (*num);
    output.rspBuffSize = &size;
    output.rspData = (char *)wattProcs;

    int ret = SendReqAndWaitForRsp(input, output);
    *num = (uint32_t)(size / sizeof(pid_t));
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetWattProcs failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetWattProcs succeed.");
    }
    return ret;
}

int AddWattProcs(const pid_t wattProcs[], uint32_t num)
{
    ReqInputParam input;
    input.optType = PROC_ADD_WATT_PROCS;
    input.dataLen = (uint32_t)sizeof(pid_t) * num;
    input.data = (char *)&wattProcs;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "AddWattProcs failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "AddWattProcs succeed.");
    }
    return ret;
}

int DelWattProcs(const pid_t wattProcs[], uint32_t num)
{
    ReqInputParam input;
    input.optType = PROC_DEL_WATT_PROCS;
    input.dataLen = (uint32_t)sizeof(pid_t) * num;
    input.data = (char *)&wattProcs;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "DelWattProcs failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "DelWattProcs succeed.");
    }
    return ret;
}


int GetSmartGridState(int *state)
{
    ReqInputParam input;
    input.optType = PROC_GET_SMART_GRID_STATE;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    uint32_t size = (uint32_t)sizeof(int);
    output.rspBuffSize = &size;
    output.rspData = (char *)state;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetSmartGridState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetSmartGridState succeed.");
    }
    return ret;
}

int SetSmartGridState(int state)
{
    ReqInputParam input;
    input.optType = PROC_SET_SMART_GRID_STATE;
    input.dataLen = (uint32_t)sizeof(state);
    input.data = (char *)&state;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetSmartGridState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetSmartGridState succeed.");
    }
    return ret;
}

int GetSmartGridProcs(PWR_PROC_SMART_GRID_LEVEL level, PWR_PROC_SmartGridProcs *sgProcs)
{
    ReqInputParam input;
    input.optType = PROC_GET_SMART_GRID_PROCS;
    input.dataLen = (uint32_t)sizeof(level);
    input.data = (char *)&level;

    RspOutputParam output;
    uint32_t size = (uint32_t)(sizeof(PWR_PROC_SmartGridProcs) + sizeof(pid_t) * (sgProcs->procNum));
    output.rspBuffSize = &size;
    output.rspData = (char *)sgProcs;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetSmartGridProcs failed. ret:%d", ret);
    } else {
        sgProcs->procNum = (size - sizeof(PWR_PROC_SmartGridProcs)) / sizeof(pid_t);
        PwrLog(DEBUG, "GetSmartGridProcs succeed.");
    }
    return ret;
}

int SetSmartGridLevel(const PWR_PROC_SmartGridProcs *sgProcs)
{
    ReqInputParam input;
    input.optType = PROC_SET_SMART_GRID_PROCS_LEVEL;
    input.dataLen = (uint32_t)(sizeof(PWR_PROC_SmartGridProcs) + sizeof(pid_t) * (sgProcs->procNum));
    input.data = (char *)sgProcs;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetSmartGridState failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetSmartGridState succeed.");
    }
    return ret;
}

int GetSmartGridGov(PWR_PROC_SmartGridGov *sgGov)
{
    ReqInputParam input;
    input.optType = PROC_GET_SMART_GRID_GOV;
    input.dataLen = 0;
    input.data = NULL;

    RspOutputParam output;
    uint32_t size = (uint32_t)sizeof(PWR_PROC_SmartGridGov);
    output.rspBuffSize = &size;
    output.rspData = (char *)sgGov;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "GetSmartGridGov failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "GetSmartGridGov succeed.");
    }
    return ret;
}

int SetSmartGridGov(const PWR_PROC_SmartGridGov *sgGov)
{
    ReqInputParam input;
    input.optType = PROC_SET_SMART_GRID_GOV;
    uint32_t size = (uint32_t)sizeof(PWR_PROC_SmartGridGov);
    input.dataLen = size;
    input.data = (char *)sgGov;

    RspOutputParam output;
    output.rspBuffSize = NULL;
    output.rspData = NULL;

    int ret = SendReqAndWaitForRsp(input, output);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "SetSmartGridGov failed. ret:%d", ret);
    } else {
        PwrLog(DEBUG, "SetSmartGridGov succeed.");
    }
    return ret;
}
