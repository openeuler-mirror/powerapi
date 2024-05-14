/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: heppen
 * Create: 2024-04-30
 * Description: provide hbm get and set interface
 * **************************************************************************** */

#ifndef PAPIS_HBM_SERVICE_H__
#define PAPIS_HBM_SERVICE_H__

#include "pwrmsg.h"
#include "pwrdata.h"

void GetHbmSysState(PwrMsg *req);
void SetHbmAllPowerState(PwrMsg *req);

#endif  //!PAPIS_HBM_SERVICE_H__