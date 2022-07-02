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
 * Description: pwrclient manager. pwrclient refers to the socket connection info.
 * **************************************************************************** */
#include <errno.h>
#include <unistd.h>
#include "pwrclient.h"
#include "pwrerr.h"
#include "common.h"
#include "log.h"


static int FindAvailableSlot(PwrClient clients[])
{
    for (int i = 0; i < MAX_LICENT_NUM; i++) {
        if (clients[i].fd == INVALID_FD) {
            return i;
        }
    }
    return INVALID_INDEX;
}

static int GetClientIdx(PwrClient clients[], PwrClient newClient)
{
    for (int i = 0; i < MAX_LICENT_NUM; i++) {
        if (clients[i].sysId == newClient.sysId) {
            return i;
        }
    }
    return INVALID_INDEX;
}

void InitPwrClient(PwrClient clients[])
{
    for (int i = 0; i < MAX_LICENT_NUM; i++) {
        clients[i].fd = INVALID_FD;
        clients[i].sysId = INVALID_INDEX;
    }
}

int AddToClientList(PwrClient clients[], PwrClient newClient)
{
    if (newClient.fd == INVALID_FD) {
        return ERR_INVALIDE_PARAM;
    }
    // reconnect scenario, update the fd
    int existIdx = GetClientIdx(clients, newClient);
    if (existIdx != INVALID_INDEX) {
        close(clients[existIdx].fd);
        clients[existIdx].fd = newClient.fd;
        return SUCCESS;
    }
    // new client
    int index = FindAvailableSlot(clients);
    if (index == INVALID_INDEX) {
        Logger(ERROR, MD_NM_SVR, "Maximum client num : %d errno :%d\n", MAX_LICENT_NUM, errno);
        return ERR_OVER_MAX_CONNECTION;
    } else {
        clients[index] = newClient;
        return SUCCESS;
    }
}


int DeleteFromClientList(PwrClient clients[], int idx)
{
    if (idx < 0 || idx >= MAX_LICENT_NUM) {
        return ERR_INVALIDE_PARAM;
    }
    close(clients[idx].fd);
    clients[idx].fd = INVALID_FD;
    clients[idx].sysId = INVALID_INDEX;
    return SUCCESS;
}

void CloseAllConnections(PwrClient clients[])
{
    for (int i = 0; i < MAX_LICENT_NUM; i++) {
        if (clients[i].fd == INVALID_FD) {
            continue;
        }
        close(clients[i].fd);
        clients[i].fd = INVALID_FD;
        clients[i].sysId = INVALID_INDEX;
    }
}

int GetFdBySysId(const PwrClient clients[], uint32_t sysId)
{
    for (int i = 0; i < MAX_LICENT_NUM; i++) {
        if (clients[i].sysId == sysId) {
            return clients[i].fd;
        }
    }
    return INVALID_FD;
}

int GetIdxByFd(const PwrClient clients[], int fd)
{
    for (int i = 0; i < MAX_LICENT_NUM; i++) {
        if (clients[i].fd == fd) {
            return i;
        }
    }
    return INVALID_INDEX;
}