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
 * Author: queyanwen
 * Create: 2022-06-23
 * Description: loading config file and manager all config items for the PowerAPI service
 * **************************************************************************** */

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include "string.h"
#include "pwrerr.h"
#include "log.h"
#include "utils.h"

static struct LogCfg g_logCfg;
inline LogCfg *GetLogCfg(void)
{
    return (LogCfg *)&g_logCfg;
}

static struct ServCfg g_servCfg;
inline ServCfg *GetServCfg(void)
{
    return (ServCfg *)&g_servCfg;
}

static char g_configPath[MAX_PATH_NAME] = "/etc/sysconfig/pwrapis/pwrapis_config.ini";

int UpdateConfigPath(const char* configPath)
{
    if (!configPath) {
        Logger(ERROR, MD_NM_CFG, "Update config path failed.");
        return ERR_NULL_POINTER;
    }
    if (access(configPath, F_OK) != 0) {
        Logger(ERROR, MD_NM_CFG, "The specified configuration file does not exist");
        return ERR_INVALIDE_PARAM;
    }
    
    strncpy(g_configPath, configPath, sizeof(g_configPath) - 1);
    return SUCCESS;
}

static int UpdateLogLevel(enum LogLevel logLevel)
{
    // Need mutex....
    g_logCfg.logLevel = logLevel;
    return SUCCESS;
}

static int UpdateLogCfg(enum CnfItemType type, char *value)
{
    int actualValue;
    switch (type) {
        case E_CFG_IT_FLS:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue <= 0) {
                Logger(ERROR, MD_NM_CFG, "File_size in config is invalid");
                return ERR_INVALIDE_PARAM;
            }
        
            g_logCfg.maxFileSize = actualValue * UNIT_FACTOR - MAX_LINE_LENGTH;
            break;
        case E_CFG_IT_CNT:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue <= 0) {
                Logger(ERROR, MD_NM_CFG, "Cmp_cnt in config is invalid");
                return ERR_INVALIDE_PARAM;
            }

            g_logCfg.maxCmpCnt = actualValue;
            break;
        case E_CFG_IT_LGV:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                Logger(ERROR, MD_NM_CFG, "Log_level in config is invalid");
                return ERR_INVALIDE_PARAM;
            }
        
            UpdateLogLevel(actualValue);
            break;
        case E_CFG_IT_LGP:
            strncpy(g_logCfg.logPath, value, sizeof(g_logCfg.logPath) - 1);
            break;
        case E_CFG_IT_BKP:
            strncpy(g_logCfg.logBkp, value, sizeof(g_logCfg.logBkp) - 1);
            break;
        case E_CFG_IT_PFX:
            strncpy(g_logCfg.logPfx, value, sizeof(g_logCfg.logPfx) - 1);
            char strFlRgx[MAX_NAME] = {0};
            if (sprintf(strFlRgx, "^%s-[[:digit:]]{14}.tar.gz$", g_logCfg.logPfx) < 0) {
                return ERR_SYS_EXCEPTION;
            }
            break;
        default:
            break;
    }
    return SUCCESS;
}

static int UpdateServCfg(enum CnfItemType type, char *value)
{
    int actualValue;
    switch (type) {
        case E_CFG_IT_SVP:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0 || actualValue > MAX_SERVER_PORT) {
                Logger(ERROR, MD_NM_CFG, "Port in config is invalid");
                return ERR_INVALIDE_PARAM;
            }

            g_servCfg.port = actualValue;
            break;
        case E_CFG_IT_SKF:
            if (access(value, F_OK) != 0) {
                Logger(ERROR, MD_NM_CFG, "Sock_file in config is invalid");
                return ERR_INVALIDE_PARAM;
            }

            strncpy(g_servCfg.sockFile, value, sizeof(g_servCfg.sockFile) - 1);
            break;
        default:
            break;
    }
    return SUCCESS;
}

static int InitLogCfg(void)
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

static int InitServCfg(void)
{
    strncpy(g_servCfg.sockFile, DEFAULT_SERVER_ADDR, sizeof(g_servCfg.sockFile) - 1);
    g_servCfg.port = 0;
    return SUCCESS;
}

static enum CnfItemType StringToEnum(char *str)
{
    if (strcmp(str, CFG_IT_FLS) == 0) {
        return E_CFG_IT_FLS;
    } else if (strcmp(str, CFG_IT_CNT) == 0) {
        return E_CFG_IT_CNT;
    } else if (strcmp(str, CFG_IT_LGV) == 0) {
        return E_CFG_IT_LGV;
    } else if (strcmp(str, CFG_IT_LGP) == 0) {
        return E_CFG_IT_LGP;
    } else if (strcmp(str, CFG_IT_BKP) == 0) {
        return E_CFG_IT_BKP;
    } else if (strcmp(str, CFG_IT_PFX) == 0) {
        return E_CFG_IT_PFX;
    } else if (strcmp(str, CFG_IT_SVP) == 0) {
        return E_CFG_IT_SVP;
    } else if (strcmp(str, CFG_IT_SKF) == 0) {
        return E_CFG_IT_SKF;
    }
}

static int LoadConfigFile(void)
{
    char line[MAX_LINE_NUM] = {0};

    FILE *fp = fopen(g_configPath, "r");
    if (fp == NULL) {
        return ERR_NULL_POINTER;
    }
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        // 空行、注释行等跳过
        if (strlen(line) <= 1 || line[0] == '#' || line[0] == '[') {
            continue;
        }
        // 解析当前行内容，提取（关键字，值），暂时默认配置文件中的key和value的格式为：key=value，不存在空格情况
        char key[MAX_KEY_LEN] = {0};
        char value[MAX_LINE_LENGTH] = {0};
        char *index = strchr(line, '=');
        if (index == NULL) {
            continue;
        }
        
        strncpy(key, line, index - line);
        strncpy(value, index + 1, sizeof(value));
        LRtrim(key);
        LRtrim(value);
        if (strlen(key) == 0 || strlen(value) == 0) {
            // key or value is invalid
            continue;
        }
        enum CnfItemType type = StringToEnum(key);
        
        switch (type) {
            case E_CFG_IT_FLS:
            case E_CFG_IT_CNT:
            case E_CFG_IT_LGV:
            case E_CFG_IT_LGP:
            case E_CFG_IT_BKP:
            case E_CFG_IT_PFX:
                UpdateLogCfg(type, value);
                break;
            case E_CFG_IT_SVP:
            case E_CFG_IT_SKF:
                UpdateServCfg(type, value);
                break;
            default:
                break;
        }
    }
    pclose(fp);
    return SUCCESS;
}

int InitConfig(void)
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

int CheckAndUpdateConfig(void)
{
    // todo 检查配置文件是否有更新，有更新则更新系统配置项
}

int GetLogLevel(void)
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
