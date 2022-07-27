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
 * Description: Provide service for PowerAPI refer to NET.
 * **************************************************************************** */
#ifndef __POWERAPI_NET_H__
#define __POWERAPI_NET_H__

#include "powerapi.h"

int GetNetInfo(PWR_NET_Info *netInfo, uint32_t bufferSize);
int GetNetThrough(char ethName[], PWR_NET_Through *ethThrough);
int GetNetSpeedMod(char ethName[], uint32_t *speedMod);
int SetNetSpeedMod(char ethName[], uint32_t speedMod);

#endif
