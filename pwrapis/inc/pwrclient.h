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
 * Description: pwrclient manager. pwrclient refers to the socket connection info.
 * **************************************************************************** */
#ifndef __PAPIS_CLIENT_H__
#define __PAPIS_CLIENT_H__

#include <stdint.h>
typedef struct PwrClient {
    int fd;
    int sysId;
} PwrClient;

void InitPwrClient(PwrClient clients[]);
int AddToClientList(PwrClient clients[], PwrClient newClient);
int DeleteFromClientList(PwrClient clients[], int idx);
void CloseAllConnections(PwrClient clients[]);
int GetFdBySysId(const PwrClient clients[], uint32_t sysId);
int GetIdxByFd(const PwrClient clients[], int fd);
#endif
