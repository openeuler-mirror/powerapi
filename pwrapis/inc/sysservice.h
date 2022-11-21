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
 * Author: wuhaotian
 * Create: 2022-11-10
 * Description: provide sys service
 * **************************************************************************** */
#ifndef PAPIS_SYS_SERVICE_H__
#define PAPIS_SYS_SERVICE_H__
#include "pwrmsg.h"
#include "pwrdata.h"

int PowerSet(char *state);
void SetSysPowerState(PwrMsg *req);
void GetSysRtPowerInfo(PwrMsg *req);
#endif
