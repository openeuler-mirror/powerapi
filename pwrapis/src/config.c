/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022 All rights reserved.
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
 * Description: loading config file and manager all config items for the PowerAPI service
 * **************************************************************************** */

#include "config.h"
#include "string.h"
#include "pwrerr.h"
#include "log.h"

static struct LogCfg g_logCfg;
inline LogCfg *GetLogCfg()
{
    return (LogCfg *)&g_logCfg;
}

static struct ServCfg g_servCfg;
inline ServCfg *GetServCfg()
{
    return (ServCfg *)&g_servCfg;
}

static int InitLogCfg()
{
    bzero(&g_logCfg, sizeof(g_logCfg));
    g_logCfg.logLevel = DEBUG; // todo 发布时修改为INFO
    g_logCfg.maxFileSize = DEFAULT_FILE_SIZE * UNIT_FACTOR - MAX_LINE_LENGTH;
    g_logCfg.maxCmpCnt = DEFAULT_FILE_NUM;
    strncpy(g_logCfg.logPath, DEFAULT_LOG_PATH, sizeof(g_logCfg.logPath) - 1);
    strncpy(g_logCfg.logBkp, DEFAULT_LOG_PATH_BAK, sizeof(g_logCfg.logBkp) - 1);
    strncpy(g_logCfg.logPfx, DEFAULT_LOG_PFX, sizeof(g_logCfg.logPfx) - 1);

    char strFlRgx[MAX_NAME] = {0};
    if (sprintf(strFlRgx, "^%s-[[:digit:]]{14}.tar.gz$", g_logCfg.logPfx) < 0) {
        return ERR_SYS_EXCEPTION;
    }
    return SUCCESS;
}

static int LoadConfigFile()
{
    // todo 打开读取文件，解析配置项，校验配置项，有效配置项替换
}
static int InitServCfg()
{
    strncpy(g_servCfg.sockFile, DEFAULT_SERVER_ADDR, sizeof(g_servCfg.sockFile) - 1);
    g_servCfg.port = 0;
    return SUCCESS;
}


int InitConfig()
{
    int ret = SUCCESS;
    // Init by default values
    ret = InitLogCfg();
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_CFG, "Init log config failed. ret:%d", ret);
        return ret;
    }

    ret = InitServCfg();
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_CFG, "Init server config failed. ret:%d", ret);
        return ret;
    }

    // load config file
    ret = LoadConfigFile();
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_CFG, "config file error. ret:%d", ret);
        return ret;
    }
    return SUCCESS;
}

int CheckAndUpdateConfig()
{
    // todo 检查配置文件是否有更新，有更新则更新系统配置项
}

int UpdateLogLevel(enum LogLevel logLevel)
{
    // Need mutex....
    g_logCfg.logLevel = logLevel;
    return SUCCESS;
}

int GetLogLevel()
{
    return g_logCfg.logLevel;
}

static enum LogLevel CauLeve(int level)
{
    enum LogLevel lgLvl;
    switch (level) {
        case DEBUG:
            lgLvl = DEBUG;
            break;
        case INFO:
            lgLvl = INFO;
            break;
        case WARNING:
            lgLvl = WARNING;
            break;
        default:
            lgLvl = ERROR;
    }
    return lgLvl;
}
