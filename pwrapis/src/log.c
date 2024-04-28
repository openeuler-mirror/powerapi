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
 * Description: provide log service
 * **************************************************************************** */
#include <log.h>

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>


#include "config.h"
#include "pwrerr.h"
#include "utils.h"

#define CRT_DIR_MODE 0700

static FILE *g_pFile = NULL; // 需要mutex保护?
static uint32_t g_curSize = 0;
static regex_t g_logCmpFlRgx;

static FILE *OpenLogFile(void)
{
    struct stat st;
    char fullName[MAX_FULL_NAME] = {0};

    // Create log file
    if (sprintf(fullName, "%s/%s", GetLogCfg()->logPath, GetLogCfg()->logPfx) < 0) {
        return NULL;
    }
    g_pFile = fopen(fullName, "a");
    if (stat(fullName, &st) < 0) {
        return NULL;
    }
    g_curSize = st.st_size;
    return g_pFile;
}

static int LogCmpFileFilter(const struct dirent *item)
{
    if (item->d_type == DT_REG) {
        if (regexec(&g_logCmpFlRgx, item->d_name, 0, NULL, 0) == 0) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}
// Release space by deleting the earlier compressed files
static void SpaceChkAndDel(void)
{
    int cnt;
    int fileCnt;
    const char *fileName = NULL;
    const char *pTmpPth = NULL;
    struct dirent **fileList = NULL;
    char fullPath[MAX_FILE_NAME] = {0};

    pTmpPth = GetLogCfg()->logBkp;
    fileCnt = scandir(pTmpPth, &fileList, LogCmpFileFilter, alphasort);
    cnt = fileCnt > GetLogCfg()->maxCmpCnt ? fileCnt - GetLogCfg()->maxCmpCnt : 0;
    // Delete old compressed files
    while (fileCnt--) {
        if (fileCnt < cnt) {
            fileName = fileList[fileCnt]->d_name;
            if (sprintf(fullPath, "%s/%s", GetLogCfg()->logBkp, fileName) < 0) {
                perror("set full path error!!!");
            }
            if (unlink(fullPath) != 0) {
                perror("delete file error!!!");
            }
        }
        free(fileList[fileCnt]);
    }
    free(fileList);
}

static int RotateFile(void)
{
    int ret;
    char curTime[MAX_STD_TIME] = {0};
    char cmdLine[MAX_LINE_NUM] = {0};
    char bakName[MAX_FILE_NAME] = {0};

    if (g_pFile != NULL) {
        fclose(g_pFile);
        g_pFile = NULL;
    }

    GetCurFmtTmStr("%Y%m%d%H%M%S", curTime, sizeof(curTime) - 1);
    if (sprintf(bakName, "%s-%s", GetLogCfg()->logPfx, curTime) < 0) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    // Compressed file
    if (sprintf(cmdLine, " cd %s && mv %s %s && tar zcvf %s.tar.gz %s && rm %s && mv %s.tar.gz %s",
        GetLogCfg()->logPath, GetLogCfg()->logPfx, bakName, bakName, bakName, bakName, bakName,
        GetLogCfg()->logBkp) < 0) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    ret = system(cmdLine);
    if (!(ret != -1 && WIFEXITED(ret) && WEXITSTATUS(ret) == 0)) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    SpaceChkAndDel();
    // Create new log file
    if (OpenLogFile() == NULL) {
        return PWR_ERR_SYS_EXCEPTION;
    }
    return PWR_SUCCESS;
}

static const char *GetLevelName(enum LogLevel level)
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

int InitLogger(void)
{
    regcomp(&g_logCmpFlRgx, "^", REG_EXTENDED | REG_NOSUB);

    if (access(GetLogCfg()->logPath, F_OK) != 0) {
        if (MkDirs(GetLogCfg()->logPath, CRT_DIR_MODE) != PWR_SUCCESS) {
            perror("access log path failed.");
            return PWR_ERR_SYS_EXCEPTION;
        }
    }
    if (access(GetLogCfg()->logBkp, F_OK) != 0) {
        if (MkDirs(GetLogCfg()->logBkp, CRT_DIR_MODE) != PWR_SUCCESS) {
            perror("access log path failed.");
            return PWR_ERR_SYS_EXCEPTION;
        }
    }

    if (OpenLogFile() == NULL) {
        return PWR_ERR_COMMON;
    }
    return PWR_SUCCESS;
}

void ClearLogger(void)
{
    if (g_pFile != NULL) {
        fclose(g_pFile);
    }
    g_pFile = NULL;
    regfree(&g_logCmpFlRgx);
    g_curSize = 0;
}


// Check head file
void Logger(enum LogLevel level, const char *moduleName, const char *format, ...)
{
    if (level < GetLogCfg()->logLevel || !g_pFile) {
        return;
    }

    size_t logLen;
    int ret;
    va_list valist;
    char curTime[MAX_STD_TIME] = {0};
    char logLine[MAX_LOG_LINE] = {0};
    char message[MAX_LINE_NUM] = {0};
    va_start(valist, format);

    if (vsnprintf(message, sizeof(message) - 1, format, valist) < 0) {
        return;
    }
    GetCurFullTime(curTime, sizeof(curTime) - 1);
    ret = sprintf(logLine, "%s %s %s: %s\n", curTime, GetLevelName(level), moduleName, message);
    if (ret < 0) {
        return;
    }
    if (fputs(logLine, g_pFile) < 0) {
        return;
    }
    if (fflush(g_pFile) < 0) {
        return;
    }
    logLen = strlen(logLine);
    g_curSize += logLen;
    if (g_curSize > GetLogCfg()->maxFileSize) {
        if (RotateFile() != PWR_SUCCESS) {
            return;
        }
    }
}
