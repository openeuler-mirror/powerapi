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
#ifndef PAPIS_CONFIG_H__
#define PAPIS_CONFIG_H__
#include <stdint.h>
#include "common.h"
#include "list.h"

#define DEFAULT_SERVER_ADDR "pwrserver.sock"
#define DEFAULT_LOG_PATH "/opt/os_data/log"
#define DEFAULT_LOG_PATH_BAK "/opt/os_data/log/bak"
#define DEFAULT_LOG_PFX "papis.log"
#define DEFAULT_FILE_SIZE 10 // MB
#define DEFAULT_FILE_NUM 3
#define MAX_SERVER_PORT 65535
#define MD5_LEN 33

// LogCfg
enum LogLevel {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR
};

// Config Item Type
enum CnfItemType {
    E_CFG_IT_FLS,
    E_CFG_IT_CNT,
    E_CFG_IT_LGV,
    E_CFG_IT_LGP,
    E_CFG_IT_BKP,
    E_CFG_IT_PFX,
    E_CFG_IT_SVP,
    E_CFG_IT_SKF,
};

typedef struct LogCfg {
    uint64_t maxFileSize;
    uint64_t maxCmpCnt;
    enum LogLevel logLevel;
    char logPath[MAX_PATH_NAME];
    char logBkp[MAX_PATH_NAME];
    char logPfx[MAX_PATH_NAME];
} LogCfg;

// Config Item
struct CnfItem {
    char name[MAX_NAME];
    char value[MAX_VALUE];
    struct ListHead node;
};

// ServCfg
typedef struct ServCfg {
    uint16_t port;
    char sockFile[MAX_FILE_NAME];
} ServCfg;

int UpdateConfigPath(const char* configPath);
int InitConfig(void);
LogCfg *GetLogCfg(void);
ServCfg *GetServCfg(void);
int CheckAndUpdateConfig(void);
#endif
