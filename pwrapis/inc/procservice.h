/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: queyanwen
 * Create: 2023-10-19
 * Description: provide PROC service
 * **************************************************************************** */
#ifndef PAPIS_PROC_SERVICE_H__
#define PAPIS_PROC_SERVICE_H__
#include "pwrmsg.h"

void ProcQueryProcs(PwrMsg *req);
void ProcGetWattState(PwrMsg *req);
void ProcSetWattState(PwrMsg *req);
void procGetWattAttrs(PwrMsg *req);
void ProcSetWattAttrs(PwrMsg *req);
void ProcGetWattProcs(PwrMsg *req);
void ProcAddWattProcs(PwrMsg *req);
void ProcDelWattProcs(PwrMsg *req);
void ProcGetSmartGridState(PwrMsg *req);
void ProcSetSmartGridState(PwrMsg *req);
void ProcGetSmartGridProcs(PwrMsg *req);
void ProcSetSmartGridProcsLevel(PwrMsg *req);
void ProcGetSmartGridGov(PwrMsg *req);
void ProcSetSmartGridGov(PwrMsg *req);
#endif
