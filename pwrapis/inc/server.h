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
 * Description: provide server methods
 * **************************************************************************** */
#ifndef __PAPIS_SERVER_H__
#define __PAPIS_SERVER_H__
#include <stdint.h>
#include <stdio.h>
#include "pwrmsg.h"

/**
 * Init and start the server
 * Note: return connected socket fd if success;
 * return < 1 if failed
 */
int StartServer(void);
void StopServer(void);
void SendRspToClient(const PwrMsg *req, int rspCode, char *data, uint32_t len);
int SendMetadataToClient(uint32_t sysId, char *data, uint32_t len);
int SendRspMsg(PwrMsg *rsp);

#endif
