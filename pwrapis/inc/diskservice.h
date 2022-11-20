/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: chengong
 * Create: 2022-08-22
 * Description: provide disk service
 * **************************************************************************** */
#ifndef PAPIS_DISK_SERVICE_H__
#define PAPIS_DISK_SERVICE_H__
#include <stdint.h>
#include "config.h"
#include "pwrmsg.h"

#define FD_HEAD_OFT 3
#define R_MEGR_FD_NUM (FD_HEAD_OFT + 1)
#define RG_MEGR_FD_NUM (FD_HEAD_OFT + 2)
#define RKB_FD_NUM (FD_HEAD_OFT + 3)
#define RD_TICKS_FD_NUM (FD_HEAD_OFT + 4)
#define W_MEGR_FD_NUM (FD_HEAD_OFT + 5)
#define WG_MEGR_FD_NUM (FD_HEAD_OFT + 6)
#define WKB_FD_NUM (FD_HEAD_OFT + 7)
#define WR_TICKS_FD_NUM (FD_HEAD_OFT + 8)
#define TOL_TK_FD_NUM (FD_HEAD_OFT + 10)
#define RQ_TK_FD_NUM (FD_HEAD_OFT + 11)
#define DC_IOS_FD_NUM (FD_HEAD_OFT + 12)
#define DC_SECT_FD_NUM (FD_HEAD_OFT + 14)
#define DC_TICKS_FD_NUM (FD_HEAD_OFT + 15)

#define FD_NUM_DSK_NM 2
#define MAX_DSK_NM_LEN 128
#define SECTOR_TO_KB_FACTOR 2
#define QUSZ_FACTOR 1000
#define AVGSZ_FACTOR 2
#define UTIL_FACTOR 1000

typedef struct Ios {
    uint64_t rdIos;
    uint64_t wrIos;
    uint64_t dcIos;
} Ios;

typedef struct Ticks {
    uint64_t rdTicks;
    uint64_t wrTicks;
    uint64_t dcTicks;
} Ticks;

typedef struct Sectors {
    uint64_t rdSect;
    uint64_t wrSect;
    uint64_t dcSect;
} Sectors;

void InitIoColl(void);
void ClearIoColl(void);
int RegIoColl(const struct ListHead* pCollCfg);
enum ExistSt IsDskExisted(const char* pDataNm);
void GetDiskinfo(PwrMsg *req);
void GetDiskLoad(PwrMsg *req);
void GetDiskPowerStatus(PwrMsg *req);
void SetDiskPowerStatus(PwrMsg *req);
void GetDiskScsiPolicy(PwrMsg *req);
void SetDiskScsiPolicy(PwrMsg *req);
#endif
