/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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
#ifndef __POWERAPI_CONNECTION_H__
#define __POWERAPI_CONNECTION_H__
#include "pwrmsg.h"

int InitSockClient();
int FiniSockClient();

int SendMsgSyn(PwrMsg *msg, PwrMsg **rsp);
int SendReqAndWaitForRsp(PwrMsg *req, PwrMsg **rsp);
#endif
