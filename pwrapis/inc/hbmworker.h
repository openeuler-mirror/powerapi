/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangyi
 * Create: 2026-09-17
 * Description: provide HBM request worker interfaces
 * **************************************************************************** */
#ifndef PAPIS_HBM_WORKER_H
#define PAPIS_HBM_WORKER_H

#include "pwrmsg.h"

int StartHbmWorker(void);
/* Stops accepting work, discards queued requests, and joins the active worker.
 * A blocked kernel operation can delay this join; this is not forced cancellation.
 * Start/stop must be serialized by the server lifecycle owner.
 */
void StopHbmWorker(void);
/* Success transfers ownership of req and req->data. Failure leaves both with caller. */
int SubmitHbmRequest(PwrMsg *req);

#endif
