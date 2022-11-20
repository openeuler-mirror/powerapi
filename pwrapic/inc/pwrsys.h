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
 * Create: 2022-11-14
 * Description: Provide service for PowerAPI refer to SYS.
 * **************************************************************************** */
#ifndef POWERAPI_SYS_H__
#define POWERAPI_SYS_H__

#include <stdint.h>
#include "pwrdata.h"

int SetSysPowerState(int powerState);
int GetSysRtPowerInfo(PWR_SYS_PowerInfo *powerInfo);
#endif
