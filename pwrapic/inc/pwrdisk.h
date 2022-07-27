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
 * Description: Provide service for PowerAPI refer to disk.
 * **************************************************************************** */
#ifndef __POWERAPI_DISK_H__
#define __POWERAPI_DISK_H__

#include "powerapi.h"

int GetDiskList(char diskList[][MAX_ELEMENT_NAME_LEN], uint32_t *len);
int GetDiskLoad(PWR_DISK_Load load[], uint32_t *len, int spec);
int GetDiskPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t *len, int spec);
int SetDiskPwrLevel(PWR_DISK_PwrLevel pwrLevel[], uint32_t len);
int GetDiskScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t *len, int spec);
int SetDiskScsiPolicy(PWR_DISK_ScsiPolicy scsiPolicy[], uint32_t len);
#endif
