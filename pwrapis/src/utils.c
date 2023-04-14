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
 * Author: luocaimin
 * Create: 2022-03-29
 * Description: provide common methods
 * **************************************************************************** */
#include "utils.h"
#include "pwrerr.h"
#include "pwrdata.h"

#include <regex.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <common.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SUCCESS 0

static struct timeval GetCurTv(void)
{
    struct timeval curTime;
    gettimeofday(&curTime, NULL);
    return curTime;
}
// Check head file
time_t GetCurSec(void)
{
    struct timeval tv;
    tv = GetCurTv();
    return tv.tv_sec;
}

static const unsigned int g_crcTable[CRC_TB_LEN] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

const char *GetCurFmtTmStr(const char *fmt, char *strTime, int bufLen)
{
    char strStdTime[MAX_STD_TIME] = {0};
    struct timeval curTime;
    struct tm *tmp = NULL;
    struct tm tmpTm;

    if (fmt == NULL) {
        return NULL;
    }
    curTime = GetCurTv();
    tmp = localtime_r(&curTime.tv_sec, &tmpTm);
    if (strftime(strStdTime, sizeof(strStdTime), fmt, tmp) < 0) {
        return NULL;
    }
    if (strlen(strStdTime) > bufLen - 1) {
        return NULL;
    }
    strcpy(strTime, strStdTime);
    return strTime;
}

// Check head file
const char *GetCurFullTime(char *fullTime, int bufLen)
{
    int res;
    char strTime[MAX_FULL_TIME] = {0};
    char strStdTime[MAX_STD_TIME] = {0};
    struct timeval curTime;
    struct tm *tmp = NULL;
    struct tm tmpTm;

    curTime = GetCurTv();

    tmp = localtime_r(&curTime.tv_sec, &tmpTm);
    if (strftime(strStdTime, sizeof(strStdTime), "%F %T", tmp) < 0) {
        return NULL;
    }
    res = snprintf(strTime, sizeof(strTime) - 1, "%s.%ld", strStdTime, curTime.tv_usec / MS_TO_SEC);
    if (res < 0) {
        return NULL;
    }
    if (strlen(strTime) > bufLen - 1) {
        return NULL;
    }
    strcpy(fullTime, strTime);
    return fullTime;
}

// return ms time
long GetTimeDistance(struct timeval v1, struct timeval v2)
{
    return (v1.tv_sec - v2.tv_sec) * THOUSAND + (v1.tv_usec - v2.tv_usec) / THOUSAND;
}

size_t GetFileSize(const char *fileName)
{
    int res = 0;
    struct stat fileStat;

    if (fileName == NULL || access(fileName, F_OK) != 0) {
        return res;
    }
    bzero(&fileStat, sizeof(fileStat));
    res = stat(fileName, &fileStat);
    if (res != 0) {
        return 0;
    }
    return fileStat.st_size;
}

int GetFileLines(const char *file, int *num)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int *p = num;

    if (file == NULL) {
        return ERR_INVALIDE_PARAM;
    }
    fp = fopen(file, "r");
    if (fp == NULL) {
        return ERR_NULL_POINTER;
    }

    *p = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        *p++;
    }

    if (line) {
        free(line);
    }
    if (fclose(fp) < 0) {
        return ERR_COMMON;
    }
    return SUCCESS;
}

static int Strptime(const char *strTime, struct tm *pTm)
{
    int inNum;
    if (pTm == NULL || strTime == NULL || strlen(strTime) < MIN_TM_LEN || !IsNumStr(strTime)) {
        return FAILED;
    }
    inNum = sscanf(strTime, "%4d%2d%2d%2d%2d%2d", &(pTm->tm_year), &(pTm->tm_mon), &(pTm->tm_mday), &(pTm->tm_hour),
        &(pTm->tm_min), &(pTm->tm_sec));
    if (inNum < TM_SEC_NUM) {
        return FAILED;
    }
    pTm->tm_year -= STC_TM_S_YEAR;
    pTm->tm_mon -= 1;
    return SUCCESS;
}
/**
 * StrTime2Sec - Convert strTime with format(20201206134723) to seconds
 */
time_t StrTime2Sec(const char *strTime)
{
    struct tm tmpTm;

    if (strTime == NULL) {
        return 0;
    }
    bzero(&tmpTm, sizeof(struct tm));
    if (Strptime(strTime, &tmpTm) != SUCCESS) {
        return 0;
    }
    return mktime(&tmpTm);
}
time_t GetLastDaySec(const char *day)
{
    char strSec[MAX_FULL_TIME] = {0};
    if (day == NULL) {
        return 0;
    }
    if (snprintf(strSec, sizeof(strSec) - 1, "%s235959", day) < 0) {
        return 0;
    }
    return StrTime2Sec(strSec);
}
time_t GetLastCurDaySec(void)
{
    const char *pDay = NULL;
    char strCurTm[MAX_STD_TIME] = {0};
    pDay = GetCurFmtTmStr("%Y%m%d", strCurTm, sizeof(strCurTm) - 1);
    return GetLastDaySec(pDay);
}
/**
 * GetNthField - Find the @nth field separated by @sep in the string
 *
 * @src : Source string
 * @sep : Separating substrings, where each character
 * and combination is a separator string
 * @nth : the N'th filed
 * @pField: filed buf
 * Note : return the start position in the @src if success
 * return NULL if others
 */
const char *GetNthField(const char *src, const char *sep, int nth, char *pField, size_t bufLen)
{
    size_t tmpLen = 0;
    const char *ps = src;
    const char *ptail = NULL;

    if (src == NULL || sep == NULL || pField == NULL || nth < 1 || bufLen < 0) {
        return NULL;
    }
    ptail = src + strlen(src);
    while (ps < ptail && nth--) {
        // Find the true starting position
        ps += tmpLen;
        tmpLen = strspn(ps, sep);
        ps = ps + tmpLen;
        if (ps >= ptail) {
            return NULL;
        }
        // Calculate effective length
        tmpLen = strcspn(ps, sep);
    }
    if (nth == -1) {
        if (bufLen < tmpLen) {
            return NULL;
        }
        strncpy(pField, ps, tmpLen);
        pField[tmpLen] = '\0';
        return pField;
    } else {
        return NULL;
    }
}

/**
 * GetNthLine - Get the @nth line string of the file
 *
 * Note : return line if success; NULL if failed;
 */
const char *GetNthLine(const char *fileName, int nth, char *lineBuf, size_t bufLen)
{
    const char *pRes = NULL;
    char line[MAX_LINE_NUM] = {0};

    if (fileName == NULL || nth < 1 || bufLen < 0) {
        return NULL;
    }

    FILE *pFile = fopen(fileName, "r");
    if (pFile == NULL) {
        return NULL;
    }
    while (nth--) {
        pRes = fgets(line, sizeof(line) - 1, pFile);
        if (pRes == NULL) {
            if (fclose(pFile) < 0) {
                return NULL;
            }
            return NULL;
        }
    }
    if (fclose(pFile) < 0) {
        return NULL;
    }
    if (bufLen < strlen(line)) {
        return NULL;
    }
    strcpy(lineBuf, line);
    return lineBuf;
}

const char *GetVal(struct FieldLocation fdLt, char *valBuf, size_t bufLen)
{
    const char *pRes = NULL;
    char lineBuf[MAX_LINE_NUM] = {0};

    if (bufLen < 0) {
        return NULL;
    }
    pRes = GetNthLine(fdLt.fileName, fdLt.lineNum, lineBuf, sizeof(lineBuf) - 1);
    if (pRes == NULL) {
        return NULL;
    }
    pRes = GetNthField(lineBuf, fdLt.sep, fdLt.fieldNum, valBuf, bufLen);
    return pRes;
}

int GetValAsInt(const char *fileName, int lineNum, int fieldNum, const char *sep)
{
    int res;
    const char *pIntRes = NULL;
    char sIntRes[MAX_VALUE] = {0};
    struct FieldLocation fdLt;

    fdLt.fileName = fileName;
    fdLt.lineNum = lineNum;
    fdLt.fieldNum = fieldNum;
    fdLt.sep = sep;

    pIntRes = GetVal(fdLt, sIntRes, sizeof(sIntRes) - 1);
    if (pIntRes == NULL) {
        res = DEFAULT_VAL;
    } else {
        if (sscanf(pIntRes, "%d", &res) < 0) {
            return DEFAULT_VAL;
        }
    }
    return res;
}
uint64_t GetValAsULong(const char *fileName, int lineNum, int fieldNum, const char *sep)
{
    uint64_t res;
    const char *pLongRes = NULL;
    char sLongRes[MAX_VALUE] = {0};
    struct FieldLocation fdLt;

    fdLt.fileName = fileName;
    fdLt.lineNum = lineNum;
    fdLt.fieldNum = fieldNum;
    fdLt.sep = sep;

    pLongRes = GetVal(fdLt, sLongRes, sizeof(sLongRes) - 1);
    if (pLongRes == NULL) {
        res = DEFAULT_VAL;
    } else {
        if (sscanf(pLongRes, "%lu", &res) < 0) {
            res = DEFAULT_VAL;
        }
    }
    return res;
}

float GetValAsFloat(const char *fileName, int lineNum, int fieldNum, const char *sep)
{
    float res = 0;
    const char *pFloatRes = NULL;
    char sFloatRes[MAX_VALUE] = {0};
    struct FieldLocation fdLt;

    fdLt.fileName = fileName;
    fdLt.lineNum = lineNum;
    fdLt.fieldNum = fieldNum;
    fdLt.sep = sep;

    pFloatRes = GetVal(fdLt, sFloatRes, sizeof(sFloatRes) - 1);
    if (pFloatRes == NULL) {
        res = DEFAULT_VAL;
    } else {
        if (sscanf(pFloatRes, "%f", &res) < 0) {
            res = DEFAULT_VAL;
        }
    }
    return res;
}

int RemoveDir(const char *dirName, int dpth)
{
    DIR *dirp = NULL;
    struct dirent *dp = NULL;
    char curDir[] = CURRENT_DIR;
    char upDir[] = PARENT_DIR;
    struct stat dirStat;
    char tmpDirName[MAX_FULL_NAME] = {0};

    if (dpth > MAX_RECU_DP) {
        return FAILED;
    }
    ++dpth;

    // The directory name does not exist, return directly
    if (dirName == NULL || access(dirName, F_OK) != 0) {
        return SUCCESS;
    }

    if (stat(dirName, &dirStat) < 0) {
        return FAILED;
    }

    if (S_ISREG(dirStat.st_mode)) {
        // Delete Files
        remove(dirName);
    } else if (S_ISDIR(dirStat.st_mode)) {
        dirp = opendir(dirName);
        while ((dp = readdir(dirp)) != NULL) {
            if ((strcmp(curDir, dp->d_name) == 0) || (strcmp(upDir, dp->d_name) == 0)) {
                continue;
            }
            sprintf(tmpDirName, "%s/%s", dirName, dp->d_name);
            // Recursively delete subdirectories
            RemoveDir(tmpDirName, dpth);
        }
        closedir(dirp);
        rmdir(dirName);
    } else {
        return FAILED;
    }
    return SUCCESS;
}

int NormalDirFiler(const struct dirent *item)
{
    if (item->d_type == DIR_ENTRY) {
        if (strcmp(item->d_name, CURRENT_DIR) == 0 || strcmp(item->d_name, PARENT_DIR) == 0) {
            return 0;
        } else {
            return 1;
        }
    } else {
        return 0;
    }
}

/**
 * MatchCnt - Returns the number of lines matching
 * the regular expression @pRegex in the file content
 * Note: return less than zero on error
 */
int MatchCnt(const char *fileName, regex_t *pRegex)
{
    int cnt = 0;
    FILE *pFile = NULL;
    char *pRdRes = NULL;
    char line[MAX_LINE_NUM] = {0};

    if (fileName == NULL || pRegex == NULL) {
        return FAILED;
    }
    if (access(fileName, F_OK | R_OK) != 0) {
        return FAILED;
    }
    pFile = fopen(fileName, "r");
    while (!feof(pFile)) {
        pRdRes = fgets(line, sizeof(line) - 1, pFile);
        if (pRdRes == NULL || feof(pFile)) {
            break;
        }
        if (regexec(pRegex, line, 0, NULL, 0) == 0) {
            ++cnt;
        }
    }
    if (fclose(pFile) < 0) {
        return cnt;
    }
    return cnt;
}

/**
 * GetMatchN - Get the Nth matching line in the file
 *
 * Note: return match line if success; NULL on error
 * Non - thread - safe functions
 *
 */
const char *GetMatchN(const char *fileName, regex_t *pRegex, int n, char *row, int bufLen)
{
    int cnt = 0;
    FILE *pFile = NULL;
    char *pRdRes = NULL;
    char line[MAX_LINE_NUM] = {0};

    if (fileName == NULL || pRegex == NULL) {
        return NULL;
    }
    if (access(fileName, F_OK | R_OK) != 0) {
        return NULL;
    }
    pFile = fopen(fileName, "r");
    while (!feof(pFile)) {
        pRdRes = fgets(line, sizeof(line) - 1, pFile);
        if (pRdRes == NULL || feof(pFile)) {
            break;
        }
        if (regexec(pRegex, line, 0, NULL, 0) == 0) {
            ++cnt;
            if (cnt == n) {
                break;
            }
        }
    }
    if (fclose(pFile)) {
        return NULL;
    }
    if (cnt == n) {
        if (strlen(line) > bufLen - 1) {
            return NULL;
        } else {
            strcpy(row, line);
            return row;
        }
    } else {
        return NULL;
    }
}

int MkDirs(const char *sDirName)
{
    int i;
    int len;
    char DirName[MAX_PATH_NAME] = {0};

    strcpy(DirName, sDirName);
    i = strlen(DirName);
    len = i;

    if (DirName[len - 1] != PATH_SEP_CHAR) {
        strcat(DirName, PATH_SEP_STR);
    }
    len = strlen(DirName);
    for (i = 1; i < len; i++) {
        if (DirName[i] == PATH_SEP_CHAR) {
            DirName[i] = '\0';
            if (access(DirName, F_OK) == 0) {
                DirName[i] = PATH_SEP_CHAR;
                continue;
            }
            if (mkdir(DirName, CRT_DIR_MODE) == -1) {
                return FAILED;
            }
            DirName[i] = PATH_SEP_CHAR;
        }
    }
    return SUCCESS;
}

unsigned int Crc32(unsigned int crc, const void *buff, unsigned int size)
{
    unsigned int i;
    const unsigned char *buffer = buff;

    for (i = 0; i < size; i++) {
        crc = g_crcTable[(crc ^ buffer[i]) & 0xff] ^ (crc >> CRC_RIGHT_SHIFT_BIT);
    }
    return crc;
}

unsigned int GetCrc32Val(const void *buffer, unsigned int bufSize)
{
    unsigned int crc = CRC_FACTOR;
    crc = Crc32(crc, buffer, bufSize);
    return crc ^ CRC_FACTOR;
}

int GetFileCrc32Val(const char *fileName, unsigned int *fileCrc)
{
    int fd = -1;
    int nread;
    unsigned char buf[CRC_FILE_BUF_LEN];
    unsigned int crc;

    if (fileCrc == NULL) {
        return FAILED;
    }
    crc = *fileCrc;

    if (fileName == NULL || fileCrc == NULL) {
        return FAILED;
    }
    fd = open(fileName, O_RDONLY);
    if (fd < 0) {
        return FAILED;
    }

    while ((nread = read(fd, buf, CRC_FILE_BUF_LEN)) > 0) {
        crc = Crc32(crc, buf, nread);
        memset(buf, 0, CRC_FILE_BUF_LEN);
    }
    close(fd);
    if (nread < 0) {
        return FAILED;
    }
    *fileCrc = crc ^ CRC_FACTOR;
    return SUCCESS;
}

int IsNumStr(const char *pStr)
{
    int len;
    int idx;
    if (pStr == NULL) {
        return 0;
    }
    len = strlen(pStr);
    for (idx = 0; idx < len; ++idx) {
        if (!isdigit(pStr[idx])) {
            return 0;
        }
    }
    return 1;
}
int NumRangeChk(const char *pStr, long min, long max)
{
    int tmp;
    tmp = 0;

    if (!IsNumStr(pStr)) {
        return 0;
    }
    if (sscanf(pStr, "%d", &tmp) < 0) {
        return 0;
    }
    if (tmp < min || tmp > max) {
        return 0;
    }
    return 1;
}
int IsPathOk(const char *path)
{
    static regex_t pthRgx;
    static const char *pPthReg = "^/((\\w|-)+/)*((\\w|-)+)?$";

    if (path == NULL) {
        return WRONG_PATH;
    }
    regcomp(&pthRgx, pPthReg, REG_EXTENDED | REG_NOSUB);
    if (regexec(&pthRgx, path, 0, NULL, 0) != 0) {
        return WRONG_PATH;
    }
    regfree(&pthRgx);
    return 1;
}

/*
 * ReadNums - Read consecutive numbers from the beginning of the string
 *
 * IN:
 * @pSrc Source string
 * @sep Field separator string
 * @maxCnt How many digits can be read at most. Nnlimited  if @maxCnt == 0
 * @arrLen The length of the integer array of the cache read result
 *
 * OUT:
 * @dts  The integer array of the cache read result
 * @pArrLen The actual number of integers read
 *
 * RETURNS: The starting position of the unread part of the string on success;
 * NULL on errors
 *
 */

const char *ReadNums(const char *pSrc, const char *sep, int maxCnt, uint64_t dts[], int *pArrLen)
{
    int readCnt;
    const char *numStart = NULL;
    const char *readPos = NULL;

    if (pSrc == NULL) {
        return NULL;
    }
    readPos = pSrc;
    readCnt = 0;
    while (*readPos != '\0') {
        if (isdigit(*readPos)) {
            if (numStart == NULL) {
                numStart = readPos;
            }
        } else if (index(sep, *readPos) != NULL) {
            if (numStart == NULL) {
                ++readPos;
                continue;
            }
            // read this num
            if (sscanf(numStart, "%lu", &dts[readCnt])) {
                return NULL;
            }
            numStart = NULL;
            ++readCnt;
            if (readCnt == *pArrLen) {
                break;
            }
            if (maxCnt != 0 && readCnt == maxCnt) {
                break;
            }
        } else {
            // Other characters are treated as ending characters
            break;
        }
        ++readPos;
    }
    if (numStart != NULL && readCnt < *pArrLen && (maxCnt == 0 || readCnt < maxCnt)) {
        // read last num
        if (sscanf(numStart, "%lu", &dts[readCnt]) < 0) {
            return NULL;
        }
        ++readCnt;
    }
    *pArrLen = readCnt;
    return readPos;
}

// Find the front nonspace postion, return char pointer
char *Ltrim(char *s)
{
    if (s == NULL) {
        return NULL;
    }
    char *t = s;
    char *p = s + strlen(s);
    while (p - t > 0 && isspace((unsigned char)(*t))) {
        t++;
    }
    return t;
}

// Find the last nonspace postion, return char pointer
char *Rtrim(char *s)
{
    if (s == NULL) {
        return NULL;
    }
    char *p = s + strlen(s);
    while (p - s > 0 && isspace((unsigned char)(*--p))) {
        *p = '\0';
    }
    return s;
}

// Remove the front and the last spaces of str.
void LRtrim(char *str)
{
    int length = strlen(str);
    int head = 0;
    int tail = length - 1;
    while (isspace(str[head])) {
        head++;
    }
    while (isspace(str[tail])) {
        tail--;
    }
    int i;
    for (i = 0; i <= tail - head; i++) {
        str[i] = str[head + i];
    }
    str[i] = '\0';
}

char *StrSplit(const char *src, const char *sep, char **res, int *itemNum)
{
    int idx;
    char *savePtr = NULL;
    char *buf = NULL;
    char *token = NULL;

    if (src == NULL || sep == NULL || res == NULL || itemNum == NULL) {
        return NULL;
    }
    buf = strdup(src);
    idx = 0;
    token = strtok_r(buf, sep, &savePtr);
    while (token != NULL && idx < *itemNum) {
        res[idx] = token;
        token = strtok_r(NULL, sep, &savePtr);
        ++idx;
    }
    *itemNum = idx;
    return buf;
}
const char *StrJoin(char **strArr, int itemNum, const char *joinStr, char *buf, int bufLen)
{
    int idx;
    int sepLen;
    int fieldLen;
    char *pos = NULL;
    char tmpBuf[MAX_LINE_LENGTH] = {0};

    if (strArr == NULL || itemNum < 1 || buf == NULL || bufLen < 1 || joinStr == NULL) {
        return NULL;
    }
    pos = tmpBuf;
    sepLen = strlen(joinStr);
    for (idx = 0; idx < itemNum - 1; ++idx) {
        if (sprintf(pos, "%s%s", strArr[idx], joinStr) < 0) {
            continue;
        }
        fieldLen = strlen(strArr[idx]);
        pos += (fieldLen + sepLen);
    }
    strcat(pos, strArr[idx]);
    if (strlen(tmpBuf) > bufLen) {
        return NULL;
    }
    strcpy(buf, tmpBuf);
    return buf;
}

const char *StrReplace(const char *src, const char *old, const char *new, char *dest, int destLen)
{
    int maxNum;
    char **res = NULL;
    char *buf = NULL;
    const char *pStrRes = NULL;

    if (src == NULL || old == NULL || new == NULL || dest == NULL || destLen < 1) {
        return NULL;
    }

    maxNum = strlen(src);
    res = calloc(maxNum, sizeof(char *));
    buf = StrSplit(src, old, res, &maxNum);
    if (buf == NULL) {
        free(res);
        return NULL;
    }

    pStrRes = StrJoin(res, maxNum, new, dest, destLen);
    free(buf);
    free(res);
    return pStrRes;
}

void DeleteChar(char str[], char a)
{
    int strLength = strlen(str);
    int point = 0;
    for (int i = 0; i < strLength; i++) {
        if ((str[i] == a)) {
            continue;
        } else {
            str[point] = str[i];
            point++;
        }
    }
    str[point] = '\0';
}

char *StrMatch(char *str, char *want)
{
    char *a = str;
    char *b = want;
    while (*b != '\0') {
        if (*a++ != *b++) {
            return NULL;
        }
    }
    return a;
}

int DeleteSubstr(char *str, char *substr)
{
    char *a = str;
    char *next;
    while (*a != '\0') {
        next = StrMatch(a, substr);
        if (next != NULL) {
            break;
        }
        a++;
    }
    if (*a == '\0') {
        return 0;
    }
    while (*a != '\0') {
        *a++ = *next++;
    }
    return 1;
}

void StrCopy(char *dest, const char *src, int destSize)
{
    unsigned int len = strlen(src) < destSize ? strlen(src) : destSize - 1;
    strncpy(dest, src, len);
    dest[len] = '\0';
}

int InIntRange(int *range, int len, int a)
{
    int i;
    for (i = 0; i < len; i++) {
        if (range[i] == a) {
            return 0;
        }
    }
    return 1;
}

int ReadFile(const char *strInfo, char *buf, int bufLen)
{
    int fd = open(strInfo, O_RDONLY);
    if (fd == -1) {
        return 1;
    }
    if (read(fd, buf, bufLen - 1) <= 0) {
        close(fd);
        return 1;
    }
    close(fd);
    DeleteChar(buf, '\n');
    buf[strlen(buf)] = '\0';
    return 0;
}

int WriteFile(const char *strInfo, char *buf, int bufLen)
{
    FILE *fp = fopen(strInfo, "w+");
    if (fp == NULL) {
        return 1;
    }
    if (fprintf(fp, "%s", buf) < 0) {
        fclose(fp);
        return 1;
    }
    if (fflush(fp) != 0) {
        fclose(fp);
        return 1;
    }
    (void)fclose(fp);
    return 0;
}

int WriteFileAndCheck(const char *strInfo, char *buf, int bufLen)
{
    if (WriteFile(strInfo, buf, bufLen) != 0) {
        return 1;
    }
    char checkBuf[MAX_ELEMENT_NAME_LEN] = {0};
    if (ReadFile(strInfo, checkBuf, MAX_ELEMENT_NAME_LEN) != 0) {
        return 1;
    }
    if (strcmp(buf, checkBuf) != 0) {
        return 1;
    }
    return 0;
}