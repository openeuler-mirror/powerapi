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
 * Description: Log service
 * **************************************************************************** */
#ifndef __POWERAPI_LOG_H__
#define __POWERAPI_LOG_H__

#include <stdarg.h>

enum PwrLogLevel {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR
};

extern void (*g_pwrlog_callback)(int level, const char *fmt, va_list vl);
static inline void PwrLog(int level, const char *fmt, ...)
{
    if (g_pwrlog_callback) {
        va_list vl;
        va_start(vl, fmt);
        g_pwrlog_callback(level, fmt, vl);
        va_end(vl);
    }
}
#endif
