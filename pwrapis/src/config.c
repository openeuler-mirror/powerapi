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
#include <stdlib.h>
#include <unistd.h>
#include "string.h"
#include "pwrerr.h"
#include "pwrdata.h"
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
static char g_lastMd5[MD5_LEN] = {0};
static char** g_adminArray = NULL;
static char** g_observerArray = NULL;

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
    if (strlen(value) == 0) {
        return ERR_INVALIDE_PARAM;
    }

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
    if (strlen(value) == 0) {
        return ERR_INVALIDE_PARAM;
    }

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
            snprintf(g_servCfg.sockFile, sizeof(g_servCfg.sockFile), "%s", value);
            break;
        default:
            break;
    }
    return SUCCESS;
}

static char** UpdateRoleArrayAction(const char *value)
{
    size_t maxNum = 0;
    int i = 0;
    char** tempRoleArray = NULL;
    maxNum = strlen(value);
    if (maxNum == 0) {
        return NULL;
    }
    tempRoleArray = calloc(maxNum + 1, sizeof(char *));
    if (!tempRoleArray) {
        Logger(ERROR, MD_NM_CFG, "Calloc failed.");
        return NULL;
    }

    if (StrSplit(value, ",", tempRoleArray, &maxNum) == NULL) {
        DoReleaseWhiteList(tempRoleArray);
        tempRoleArray = NULL;
        return NULL;
    }
    while (tempRoleArray[i] != NULL) {
        LRtrim(tempRoleArray[i]);
        i++;
    }

    /**
     * If success, return temp array.
     * tempRoleArray will be release in UpdateRoleArray
    */
    return tempRoleArray;
}

static int UpdateRoleArray(enum CnfItemType type, const char *value)
{
    char** tempRoleArray = UpdateRoleArrayAction(value);
    char** oldRoleArray = NULL;
    switch (type) {
        case E_CFG_IT_ADM:
            if (value == NULL) {
                DoReleaseWhiteList(g_adminArray);
                g_adminArray = NULL;
                return SUCCESS;
            }

            if (tempRoleArray == NULL) {
                Logger(INFO, MD_NM_CFG, "Admin in config is meaningless!%s", value);
                return ERR_INVALIDE_PARAM;
            }

            oldRoleArray = g_adminArray;
            g_adminArray = tempRoleArray;
            DoReleaseWhiteList(oldRoleArray);
            oldRoleArray = NULL;
            Logger(INFO, MD_NM_CFG, "Admin in config has been modified to %s", value);
            break;
        case E_CFG_IT_OBSER:
            if (value == NULL) {
                DoReleaseWhiteList(g_observerArray);
                g_observerArray = NULL;
                Logger(INFO, MD_NM_CFG, "Observer in config has been modified to null");
                return SUCCESS;
            }

            if (tempRoleArray == NULL) {
                Logger(INFO, MD_NM_CFG, "Observer in config is meaningless!%s", value);
                return ERR_INVALIDE_PARAM;
            }

            oldRoleArray = g_observerArray;
            g_observerArray = tempRoleArray;
            DoReleaseWhiteList(oldRoleArray);
            oldRoleArray = NULL;
            Logger(INFO, MD_NM_CFG, "Obser in config has been modified to %s", value);
            break;
        default:
            DoReleaseWhiteList(tempRoleArray);
            break;
    }
    tempRoleArray = NULL;
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
    } else if (strcmp(str, CFG_IT_ADM) == 0) {
        return E_CFG_IT_ADM;
    } else if (strcmp(str, CFG_IT_OBSER) == 0) {
        return E_CFG_IT_OBSER;
    }
}

static int LoadConfigFile(void)
{
    char line[MAX_LINE_NUM] = {0};
    char realpathRes[MAX_FULL_NAME] = {0};

    int ret = NormalizeAndVerifyFilepath(g_configPath, realpathRes);
    if (ret != SUCCESS) return ret;
    if (access(realpathRes, R_OK) != 0) return ERR_COMMON;

    FILE *fp = fopen(realpathRes, "r");
    if (fp == NULL) return ERR_NULL_POINTER;
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        // Skip invalid lines such as empty lines、comment lines
        if (strlen(line) <= 1 || line[0] == '#' || line[0] == '[') {
            continue;
        }
        // Parse the current line content, extract (key, value)
        char key[MAX_KEY_LEN] = {0};
        char value[MAX_LINE_LENGTH] = {0};
        char *index = strchr(line, '=');
        if (index == NULL) continue;

        strncpy(key, line, index - line);
        strncpy(value, index + 1, MAX_LINE_LENGTH - 1);
        LRtrim(key);
        LRtrim(value);
        if (strlen(key) == 0) {
            // Key is invalid
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
            case E_CFG_IT_ADM:
            case E_CFG_IT_OBSER:
                UpdateRoleArray(type, value);
                break;
            default:
                break;
        }
    }
    if (fclose(fp) < 0) return ERR_COMMON;
    return SUCCESS;
}

int InitConfig(void)
{
    // Get initial md5 of config
    bzero(g_lastMd5, sizeof(g_lastMd5));
    GetMd5(g_configPath, g_lastMd5);
    if (strlen(g_lastMd5) == 0) {
        Logger(ERROR, MD_NM_CFG, "Get initial md5 of config failed");
        return FAILED;
    }

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
        Logger(ERROR, MD_NM_CFG, "Handle config file failed. ret:%d", ret);
        return ret;
    }
    return SUCCESS;
}

static int HandleInvalidUpdate(char *key, char *value)
{
    enum CnfItemType type = StringToEnum(key);
    switch (type) {
        case E_CFG_IT_LGP:
            if (strcmp(value, g_logCfg.logPath) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return ERR_COMMON;
            }
            break;
        case E_CFG_IT_BKP:
            if (strcmp(value, g_logCfg.logBkp) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return ERR_COMMON;
            }
            break;
        case E_CFG_IT_PFX:
            if (strcmp(value, g_logCfg.logPfx) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return ERR_COMMON;
            }
            break;
        case E_CFG_IT_SKF:
            if (strcmp(value, g_servCfg.sockFile) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return ERR_COMMON;
            }
            break;
    }
    return SUCCESS;
}

int UpdateConfig(char *key, char *value)
{
    enum CnfItemType type = StringToEnum(key);
    int actualValue;
    switch (type) {
        // Properties that can be dynamically validated
        case E_CFG_IT_FLS:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                int curFileSize = (g_logCfg.maxFileSize + MAX_LINE_LENGTH) / UNIT_FACTOR;
                Logger(ERROR, MD_NM_CFG, "File_size in config is invalid, current valid value is %d", curFileSize);
                return ERR_INVALIDE_PARAM;
            }
            int maxFileSize = actualValue * UNIT_FACTOR - MAX_LINE_LENGTH;
            if (maxFileSize != g_logCfg.maxFileSize) {
                g_logCfg.maxFileSize = maxFileSize;
                Logger(INFO, MD_NM_CFG, "File_size in config has been modified to %d", actualValue);
            }
            break;
        case E_CFG_IT_CNT:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                Logger(ERROR, MD_NM_CFG, "Cmp_cnt in config is invalid, current valid value is %d", g_logCfg.maxCmpCnt);
                return ERR_INVALIDE_PARAM;
            }
            if (actualValue != g_logCfg.maxCmpCnt) {
                g_logCfg.maxCmpCnt = actualValue;
                Logger(INFO, MD_NM_CFG, "Cmp_cnt in config has been modified to %d", actualValue);
            }
            break;
        case E_CFG_IT_LGV:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                enum LogLevel curLogLevel = g_logCfg.logLevel;
                Logger(ERROR, MD_NM_CFG, "Log_level in config is invalid, current valid value is %d", curLogLevel);
                return ERR_INVALIDE_PARAM;
            }
            if (actualValue != g_logCfg.logLevel) {
                UpdateLogLevel(actualValue);
                Logger(INFO, MD_NM_CFG, "Log_level in config has been modified to %d", actualValue);
            }
            break;
        case E_CFG_IT_ADM:
        case E_CFG_IT_OBSER:
            return UpdateRoleArray(type, value);
        // Properties that cannot be dynamically validated
        default:
            return HandleInvalidUpdate(key, value);
    }
    return SUCCESS;
}

int CheckAndUpdateConfig(void)
{
    char curMd5[MD5_LEN] = {0};
    GetMd5(g_configPath, curMd5);
    if (strlen(curMd5) == 0 || strcmp(curMd5, g_lastMd5) == 0) {
        return SUCCESS;
    }

    int invalidUpdateSum = 0;   // The number of invalid updates
    int nonDynamicSum = 0;      // The number of undynamically validated attrs that been modified
    char line[MAX_LINE_LENGTH];
    char realpathRes[MAX_FULL_NAME] = {0};

    int ret = NormalizeAndVerifyFilepath(g_configPath, realpathRes);
    if (ret != SUCCESS) return ret;
    if (access(realpathRes, R_OK) != 0) return ERR_COMMON;

    FILE *fp = fopen(realpathRes, "r");
    if (fp == NULL) return ERR_NULL_POINTER;

    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        if (strlen(line) <= 1 || line[0] == '#' || line[0] == '[') continue;
        char key[MAX_KEY_LEN] = {0};
        char value[MAX_LINE_LENGTH] = {0};
        char *index = strchr(line, '=');
        if (index == NULL) continue;
        
        strncpy(key, line, index - line);
        strncpy(value, index + 1, sizeof(value));
        LRtrim(key);
        LRtrim(value);
        if (strlen(key) == 0 || strlen(value) == 0) {
            // key or value is invalid
            continue;
        }
        switch (UpdateConfig(key, value)) {
            case ERR_INVALIDE_PARAM:
                invalidUpdateSum++;
                break;
            case ERR_COMMON:
                nonDynamicSum++;
                break;
        }
    }
    if (fclose(fp) < 0) return ERR_COMMON;
    strncpy(g_lastMd5, curMd5, sizeof(g_lastMd5));
    /**
     * The file has been confirmed to be modified now.
     * 1. Error modifying attrs, return ERR_INVALIDE_PARAM;
     * 2. Undynamically validated attrs have been modified, return ERR_MODIFY_BAN_UPDATE_ATTR_CURRENTLY;
     * 3. Return SUCCESS.
     */
    if (invalidUpdateSum != 0) {
        return ERR_INVALIDE_PARAM;
    } else {
        if (nonDynamicSum != 0) {
            return ERR_MODIFY_BAN_UPDATE_ATTR_CURRENTLY;
        } else {
            return SUCCESS;
        }
    }
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

int IsAdmin(const char* user)
{
    int i = 0;

    if (strcmp(user, "root") == 0) {
        return TRUE;
    }
    if (g_adminArray == NULL) {
        return FALSE;
    }
    while (g_adminArray[i] != NULL) {
        if (strcmp(user, g_adminArray[i]) == 0) {
            return TRUE;
        }
        i++;
    }

    return FALSE;
}

int IsObserver(const char* user)
{
    int i = 0;

    if (g_observerArray == NULL) {
        return FALSE;
    }
    while (g_observerArray[i] != NULL) {
        if (strcmp(user, g_observerArray[i]) == 0) {
            return TRUE;
        }
        i++;
    }

    return FALSE;
}

void DoReleaseWhiteList(char** whiteList)
{
    int i = 0;
    if (!whiteList) {
        return;
    }

    while (whiteList[i] != NULL) {
        free(whiteList[i]);
        whiteList[i] = NULL;
        i++;
    }
    free(whiteList);
    whiteList = NULL;
}

void ReleaseWhiteList(void)
{
    DoReleaseWhiteList(g_adminArray);
    DoReleaseWhiteList(g_observerArray);
    g_adminArray = NULL;
    g_observerArray = NULL;
}