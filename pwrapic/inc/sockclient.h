/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: Provide IPC ability. Socket initialization, send/receive msg, send/recieve buffer
 * **************************************************************************** */
#ifndef POWERAPI_CONNECTION_H__
#define POWERAPI_CONNECTION_H__
#include "pwrmsg.h"
#include "pwrdata.h"

typedef struct ReqInputParam {
    enum OperationType optType;
    uint32_t taskNo;
    uint32_t dataLen;
    char *data;
} ReqInputParam;

typedef struct RspOutputParam {
    uint32_t *rspBuffSize;
    char *rspData;
} RspOutputParam;

int SetServerInfo(const char* socketPath);
int InitSockClient(void);
int FiniSockClient(void);
int SetMetaDataCallback(void(MetaDataCallback)(const PWR_COM_CallbackData *));
int HasSetDataCallback(void);
int SendReqAndWaitForRsp(const ReqInputParam input, RspOutputParam output);
#endif
