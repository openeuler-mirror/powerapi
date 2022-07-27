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
 * Description: provide log interface
 * **************************************************************************** */
#ifndef __PAPIS_LOG_H__
#define __PAPIS_LOG_H__

#include <stdint.h>
#include "common.h"
#include "config.h"

/**
 * InitLogger - do logger initialize operation.
 *
 * Note: Exit on error
 */

int InitLogger();
/**
 * Logger - send messages to the system logger
 *
 * @level: DEBUG < INFO < WARNING < ERROR
 */
void Logger(enum LogLevel level, const char *moduleName, const char *format, ...);

void ClearLogger();
#endif
