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
 * Create: 2022-11-15
 * Description: provide common service
 * **************************************************************************** */

#include "comservice.h"
#include <unistd.h>
#include "common.h"
#include "pwrerr.h"
#include "log.h"
#include "pwrdata.h"
#include "server.h"
#include "utils.h"
#include "config.h"
#include "pwrerr.h"

static int g_authed = PWR_FALSE;
static uint32_t g_authOwner = 0;

static int DoAuthRequest(uint32_t client)
{
    UnixCredOS credOS;
    int ret = GetSockoptFromOS(client, &credOS);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR_TASK, "get sockopt from OS failed, ret : %d", ret);
        return PWR_ERR_COMMON;
    }
    if (!IsAdmin(credOS.user)) {
        Logger(ERROR, MD_NM_SVR_TASK, "the client <%s> is not an admin", credOS.user);
        return PWR_ERR_CONTROL_AUTH_NO_PERMISSION;
    }

    if (g_authed) {
        if (g_authOwner != client) { // Control has been granted to other app
            return PWR_ERR_CONTROL_AUTH_REQUESTED;
        }
        return PWR_SUCCESS;
    }
    g_authOwner = client;
    g_authed = PWR_TRUE;
    return PWR_SUCCESS;
}

static int DoAuthRelease(uint32_t client)
{
    if (g_authed && g_authOwner == client) {
        g_authOwner = 0;
        g_authed = PWR_FALSE;
        return PWR_SUCCESS;
    }

    if (!g_authed) {
        g_authOwner = 0;
        return PWR_SUCCESS;
    }
    return PWR_ERR_CONTROL_AUTH_OWNERED_BY_OTHERS;
}

// public===========================================================================================
void RequestControlAuth(PwrMsg *req)
{
    int rspCode = DoAuthRequest(req->head.sysId);
    SendRspToClient(req, rspCode, NULL, 0);
}

void ReleaseControlAuth(PwrMsg *req)
{
    int rspCode = DoAuthRelease(req->head.sysId);
    SendRspToClient(req, rspCode, NULL, 0);
}

void CleanControlAuth(uint32_t client)
{
    DoAuthRelease(client);
}