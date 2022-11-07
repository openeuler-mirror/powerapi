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
 * Create: 2022-11-05
 * Description: provide task service
 * **************************************************************************** */
#ifndef PAPIS_TASK_SERVICE_H__
#define PAPIS_TASK_SERVICE_H__
#include "pwrmsg.h"

int InitTaskService(void);
void FiniTaskService(void);
void CreateDataCollTask(const PwrMsg *req);
void DeleteDataCollTask(const PwrMsg *req);

#endif
