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
        return PWR_ERR_NULL_POINTER;
    }
    if (access(configPath, F_OK) != 0) {
        Logger(ERROR, MD_NM_CFG, "The specified configuration file does not exist");
        return PWR_ERR_INVALIDE_PARAM;
    }

    strncpy(g_configPath, configPath, sizeof(g_configPath) - 1);
    return PWR_SUCCESS;
}

static int UpdateLogLevel(enum LogLevel logLevel)
{
    // Need mutex....
    g_logCfg.logLevel = logLevel;
    return PWR_SUCCESS;
}

static int UpdateLogCfg(enum CnfItemType type, char *value)
{
    int actualValue;
    if (strlen(value) == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    switch (type) {
        case E_CFG_IT_FLS:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue <= 0) {
                Logger(ERROR, MD_NM_CFG, "File_size in config is invalid");
                return PWR_ERR_INVALIDE_PARAM;
            }

            g_logCfg.maxFileSize = actualValue * UNIT_FACTOR - MAX_LINE_LENGTH;
            break;
        case E_CFG_IT_CNT:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue <= 0) {
                Logger(ERROR, MD_NM_CFG, "Cmp_cnt in config is invalid");
                return PWR_ERR_INVALIDE_PARAM;
            }

            g_logCfg.maxCmpCnt = actualValue;
            break;
        case E_CFG_IT_LGV:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                Logger(ERROR, MD_NM_CFG, "Log_level in config is invalid");
                return PWR_ERR_INVALIDE_PARAM;
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
                return PWR_ERR_SYS_EXCEPTION;
            }
            break;
        default:
            break;
    }
    return PWR_SUCCESS;
}


static void DoReleaseWhiteList(char** whiteList)
{
    int i = 0;
    if (!whiteList) {
        return;
    }

    while (i < MAX_USER_NUM && whiteList[i] != NULL) {
        free(whiteList[i]);
        whiteList[i] = NULL;
        i++;
    }
    free(whiteList);
    whiteList = NULL;
}

static int UpdateServCfg(enum CnfItemType type, char *value)
{
    int actualValue;
    if (strlen(value) == 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    switch (type) {
        case E_CFG_IT_SVP:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0 || actualValue > MAX_SERVER_PORT) {
                Logger(ERROR, MD_NM_CFG, "Port in config is invalid");
                return PWR_ERR_INVALIDE_PARAM;
            }

            g_servCfg.port = actualValue;
            break;
        case E_CFG_IT_SKF:
            snprintf(g_servCfg.sockFile, sizeof(g_servCfg.sockFile), "%s", value);
            break;
        default:
            break;
    }
    return PWR_SUCCESS;
}

static char** UpdateRoleArrayAction(const char *value)
{
    if (!value || strlen(value) == 0) {
        return NULL;
    }

    int userNum = MAX_USER_NUM;
    char** tempRoleArray = calloc(MAX_USER_NUM, sizeof(char *));
    if (!tempRoleArray) {
        Logger(ERROR, MD_NM_CFG, "Calloc failed.");
        return NULL;
    }
    char *pbuff = StrSplit(value, ",", tempRoleArray, &userNum);
    if (!pbuff) {
        free(tempRoleArray);
        return NULL;
    }

    char** users = calloc(MAX_USER_NUM, sizeof(char *));
    if (!users) {
        free(pbuff);
        free(tempRoleArray);
        return NULL;
    }
    bzero(users, MAX_USER_NUM * sizeof(char *));
    int idx = 0;
    for (int i = 0; i < userNum; i++) {
        if (!tempRoleArray[i]) {
            continue;
        }
        LRtrim(tempRoleArray[i]);
        char * user = malloc(strlen(tempRoleArray[i]) + 1);
        if (!user) {
            DoReleaseWhiteList(users);
            free(pbuff);
            free(tempRoleArray);
            return NULL;
        }

        StrCopy(user, tempRoleArray[i], strlen(tempRoleArray[i]) + 1);
        users[idx] = user;
        idx++;
    }

    /**
     * users will be release in UpdateRoleArray
    */
    free(pbuff);
    free(tempRoleArray);
    return users;
}

static int UpdateRoleArray(enum CnfItemType type, const char *value)
{
    char** tempRoleArray = UpdateRoleArrayAction(value);
    char** oldRoleArray = NULL;
    switch (type) {
        case E_CFG_IT_ADM:
            if (value == NULL) {
                // tempRoleArray must be null
                DoReleaseWhiteList(g_adminArray);
                g_adminArray = NULL;
                return PWR_SUCCESS;
            }

            if (strlen(value) != 0 && tempRoleArray == NULL) {
                Logger(INFO, MD_NM_CFG, "Admin in config is meaningless!%s", value);
                return PWR_ERR_INVALIDE_PARAM;
            }

            oldRoleArray = g_adminArray;
            g_adminArray = tempRoleArray;
            DoReleaseWhiteList(oldRoleArray);
            oldRoleArray = NULL;
            Logger(INFO, MD_NM_CFG, "Admin in config has been modified to [%s]", value);
            break;
        case E_CFG_IT_OBSER:
            if (value == NULL) {
                // tempRoleArray must be null
                DoReleaseWhiteList(g_observerArray);
                g_observerArray = NULL;
                Logger(INFO, MD_NM_CFG, "Observer in config has been modified to null");
                return PWR_SUCCESS;
            }

            if (strlen(value) != 0 && tempRoleArray == NULL) {
                Logger(INFO, MD_NM_CFG, "Observer in config is meaningless!%s", value);
                return PWR_ERR_INVALIDE_PARAM;
            }

            oldRoleArray = g_observerArray;
            g_observerArray = tempRoleArray;
            DoReleaseWhiteList(oldRoleArray);
            oldRoleArray = NULL;
            Logger(INFO, MD_NM_CFG, "Obser in config has been modified to [%s]", value);
            break;
        default:
            DoReleaseWhiteList(tempRoleArray);
            break;
    }
    tempRoleArray = NULL;
    return PWR_SUCCESS;
}

static int InitLogCfg(void)
{
    bzero(&g_logCfg, sizeof(g_logCfg));
    g_logCfg.logLevel = INFO;
    g_logCfg.maxFileSize = DEFAULT_FILE_SIZE * UNIT_FACTOR - MAX_LINE_LENGTH;
    g_logCfg.maxCmpCnt = DEFAULT_FILE_NUM;
    strncpy(g_logCfg.logPath, DEFAULT_LOG_PATH, sizeof(g_logCfg.logPath) - 1);
    strncpy(g_logCfg.logBkp, DEFAULT_LOG_PATH_BAK, sizeof(g_logCfg.logBkp) - 1);
    strncpy(g_logCfg.logPfx, DEFAULT_LOG_PFX, sizeof(g_logCfg.logPfx) - 1);

    char strFlRgx[MAX_NAME] = {0};
    if (sprintf(strFlRgx, "^%s-[[:digit:]]{14}.tar.gz$", g_logCfg.logPfx) < 0) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    return PWR_SUCCESS;
}

static int InitServCfg(void)
{
    strncpy(g_servCfg.sockFile, DEFAULT_SERVER_SOCK_FILE, sizeof(g_servCfg.sockFile) - 1);
    g_servCfg.port = 0;
    return PWR_SUCCESS;
}

static Name_To_Enum g_strToEnum[] = {
    {CFG_IT_FLS, E_CFG_IT_FLS},
    {CFG_IT_CNT, E_CFG_IT_CNT},
    {CFG_IT_LGV, E_CFG_IT_LGV},
    {CFG_IT_LGP, E_CFG_IT_LGP},
    {CFG_IT_BKP, E_CFG_IT_BKP},
    {CFG_IT_PFX, E_CFG_IT_PFX},
    {CFG_IT_SVP, E_CFG_IT_SVP},
    {CFG_IT_SKF, E_CFG_IT_SKF},
    {CFG_IT_ADM, E_CFG_IT_ADM},
    {CFG_IT_OBSER, E_CFG_IT_OBSER}
};

static enum CnfItemType NameToEnum(char *name)
{
    int len = sizeof(g_strToEnum) / sizeof(g_strToEnum[0]);
    for (int i = 0; i < len; i++) {
        if (strcmp(name, g_strToEnum[i].cnfItemName) == 0) {
            return g_strToEnum[i].cnfItemType;
        }
    }
    return -1;
}

static int ParseCfgAndHandle(int(Handler(char *name, char *value)), const char *file)
{
    char line[MAX_LINE_NUM] = {0};
    char itemName[MAX_KEY_LEN] = {0};
    char itemValue[MAX_LINE_LENGTH] = {0};

    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        return PWR_ERR_FILE_OPEN_FAILED;
    }
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        memset(itemName, 0, MAX_KEY_LEN);
        memset(itemValue, 0, MAX_LINE_LENGTH);
        if (strlen(line) <= 1 || line[0] == '#' || line[0] == '[') {
            continue;
        }
        char *index = strchr(line, '=');
        if (index == NULL) {
            continue;
        }
        strncpy(itemName, line, index - line);
        strncpy(itemValue, index + 1, MAX_LINE_LENGTH - 1);
        LRtrim(itemName);
        LRtrim(itemValue);
        if (strlen(itemName) == 0) {
            continue;
        }
        Handler(itemName, itemValue);
    }
    return PWR_SUCCESS;
}

static int LoadCfgHandler(char *itemName, char *itemValue)
{
    enum CnfItemType type = NameToEnum(itemName);

    switch (type) {
        case E_CFG_IT_FLS:
        case E_CFG_IT_CNT:
        case E_CFG_IT_LGV:
        case E_CFG_IT_LGP:
        case E_CFG_IT_BKP:
        case E_CFG_IT_PFX:
            UpdateLogCfg(type, itemValue);
            break;
        case E_CFG_IT_SVP:
        case E_CFG_IT_SKF:
            UpdateServCfg(type, itemValue);
            break;
        case E_CFG_IT_ADM:
        case E_CFG_IT_OBSER:
            UpdateRoleArray(type, itemValue);
            break;
        default:
            break;
    }
    return PWR_SUCCESS;
}
static int LoadConfigFile(void)
{
    // char line[MAX_LINE_NUM] = {0};
    char realpath[MAX_FULL_NAME] = {0};

    int ret = NormalizeAndVerifyFilepath(g_configPath, realpath);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    if (access(realpath, R_OK) != 0) {
        return PWR_ERR_COMMON;
    }
    return ParseCfgAndHandle(LoadCfgHandler, realpath);
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

    int ret = PWR_SUCCESS;
    // Init by default values
    ret = InitLogCfg();
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_CFG, "Init log config failed. ret:%d", ret);
        return ret;
    }

    ret = InitServCfg();
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_CFG, "Init server config failed. ret:%d", ret);
        return ret;
    }

    // load config file
    ret = LoadConfigFile();
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_CFG, "Handle config file failed. ret:%d", ret);
        return ret;
    }
    return PWR_SUCCESS;
}

static int HandleInvalidUpdate(char *key, char *value)
{
    enum CnfItemType type = NameToEnum(key);
    switch (type) {
        case E_CFG_IT_LGP:
            if (strcmp(value, g_logCfg.logPath) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return PWR_ERR_COMMON;
            }
            break;
        case E_CFG_IT_BKP:
            if (strcmp(value, g_logCfg.logBkp) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return PWR_ERR_COMMON;
            }
            break;
        case E_CFG_IT_PFX:
            if (strcmp(value, g_logCfg.logPfx) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return PWR_ERR_COMMON;
            }
            break;
        case E_CFG_IT_SKF:
            if (strcmp(value, g_servCfg.sockFile) != 0) {
                Logger(ERROR, MD_NM_CFG, "%s cannot be dynamically configured to take effect", key);
                return PWR_ERR_COMMON;
            }
            break;
        default:
            break;
    }
    return PWR_SUCCESS;
}

int UpdateConfig(char *key, char *value)
{
    enum CnfItemType type = NameToEnum(key);
    int actualValue;
    switch (type) {
        case E_CFG_IT_FLS:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                int curFileSize = (g_logCfg.maxFileSize + MAX_LINE_LENGTH) / UNIT_FACTOR;
                Logger(ERROR, MD_NM_CFG, "File_size in config is invalid, current valid value is %d", curFileSize);
                return PWR_ERR_INVALIDE_PARAM;
            }
            uint64_t maxFileSize = actualValue * UNIT_FACTOR - MAX_LINE_LENGTH;
            if (maxFileSize != g_logCfg.maxFileSize) {
                g_logCfg.maxFileSize = maxFileSize;
                Logger(INFO, MD_NM_CFG, "File_size in config has been modified to %d", actualValue);
            }
            break;
        case E_CFG_IT_CNT:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                Logger(ERROR, MD_NM_CFG, "Cmp_cnt in config is invalid, current valid value is %d", g_logCfg.maxCmpCnt);
                return PWR_ERR_INVALIDE_PARAM;
            }
            if ((uint64_t)actualValue != g_logCfg.maxCmpCnt) {
                g_logCfg.maxCmpCnt = actualValue;
                Logger(INFO, MD_NM_CFG, "Cmp_cnt in config has been modified to %d", actualValue);
            }
            break;
        case E_CFG_IT_LGV:
            actualValue = atoi(value);
            if (!IsNumStr(value) || actualValue < 0) {
                enum LogLevel curLogLevel = g_logCfg.logLevel;
                Logger(ERROR, MD_NM_CFG, "Log_level in config is invalid, current valid value is %d", curLogLevel);
                return PWR_ERR_INVALIDE_PARAM;
            }
            if ((uint64_t)actualValue != g_logCfg.logLevel) {
                UpdateLogLevel(actualValue);
                Logger(INFO, MD_NM_CFG, "Log_level in config has been modified to %d", actualValue);
            }
            break;
        case E_CFG_IT_ADM:
        case E_CFG_IT_OBSER:
            return UpdateRoleArray(type, value);
        default:
            return HandleInvalidUpdate(key, value);
    }
    return PWR_SUCCESS;
}

int CheckAndUpdateConfig(void)
{
    char curMd5[MD5_LEN] = {0};
    GetMd5(g_configPath, curMd5);
    if (strlen(curMd5) == 0 || strcmp(curMd5, g_lastMd5) == 0) {
        return PWR_SUCCESS;
    }
    char realpath[MAX_FULL_NAME] = {0};

    int ret = NormalizeAndVerifyFilepath(g_configPath, realpath);
    if (ret != PWR_SUCCESS) {
        return ret;
    }
    if (access(realpath, R_OK) != 0) {
        return PWR_ERR_COMMON;
    }
    strncpy(g_lastMd5, curMd5, sizeof(g_lastMd5));
    return ParseCfgAndHandle(UpdateConfig, realpath);
}

int GetLogLevel(void)
{
    return g_logCfg.logLevel;
}

int IsAdmin(const char* user)
{
    int i = 0;

    if (strcmp(user, "root") == 0) {
        return PWR_TRUE;
    }
    if (g_adminArray == NULL) {
        return PWR_FALSE;
    }
    while (g_adminArray[i] != NULL) {
        if (strcmp(user, g_adminArray[i]) == 0) {
            return PWR_TRUE;
        }
        i++;
    }

    return PWR_FALSE;
}

int IsObserver(const char* user)
{
    int i = 0;

    if (g_observerArray == NULL) {
        return PWR_FALSE;
    }
    while (g_observerArray[i] != NULL) {
        if (strcmp(user, g_observerArray[i]) == 0) {
            return PWR_TRUE;
        }
        i++;
    }

    return PWR_FALSE;
}

void ReleaseWhiteList(void)
{
    DoReleaseWhiteList(g_adminArray);
    DoReleaseWhiteList(g_observerArray);
    g_adminArray = NULL;
    g_observerArray = NULL;
}
