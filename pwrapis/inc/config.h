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
 * Description: provide configuration service
 * **************************************************************************** */
#ifndef __PAPIS_CONFIG_H__
#define __PAPIS_CONFIG_H__
#include <stdint.h>
#include <stdio.h>
#include "common.h"

#define DEFAULT_SERVER_ADDR "pwrserver.sock"
#define DEFAULT_LOG_PATH "/opt/os_data/log"
#define DEFAULT_LOG_PATH_BAK "/opt/os_data/log/bak"
#define DEFAULT_LOG_PFX "papis.log"
#define DEFAULT_FILE_SIZE 10 // MB
#define DEFAULT_FILE_NUM 3


// LogCfg
enum LogLevel {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR
};

typedef struct LogCfg {
    uint64_t maxFileSize;
    uint64_t maxCmpCnt;
    enum LogLevel logLevel;
    char logPath[MAX_PATH_NAME];
    char logBkp[MAX_PATH_NAME];
    char logPfx[MAX_PATH_NAME];
} LogCfg;


// ServCfg
typedef struct ServCfg {
    uint16_t port;
    char sockFile[MAX_FILE_NAME];
} ServCfg;

int InitConfig(void);
LogCfg *GetLogCfg(void);
ServCfg *GetServCfg(void);
int CheckAndUpdateConfig(void);
#endif
