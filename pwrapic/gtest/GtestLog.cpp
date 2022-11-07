/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jimmy-jiang-junior
 * Create: 2022-11-04
 * Description: log callback function for PowerAPI
 * **************************************************************************** */
#include "GtestLog.h"

enum {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR
};

static const char *GetLevelName(int level)
{
    static char debug[] = "DEBUG";
    static char info[] = "INFO";
    static char warning[] = "WARNING";
    static char error[] = "ERROR";
    switch (level) {
        case DEBUG:
            return debug;
        case INFO:
            return info;
        case WARNING:
            return warning;
        case ERROR:
            return error;
        default:
            return info;
    }
}

void LogCallback(int level, const char *fmt, va_list vl)
{
    char message[4000] = {0};

    if (vsnprintf(message, sizeof(message) - 1, fmt, vl) < 0) {
        return;
    }

    printf("%s: %s\n", GetLevelName(level), message);
}
