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
 * Create: 2022-06-23
 * Description: provide common methods
 * **************************************************************************** */
#ifndef __UTILS_H__
#define __UTILS_H__
#include <time.h>
#include <dirent.h>
#include <regex.h>
#include <stdint.h>
#include "config.h"

#define DIR_ENTRY 4
#define TM_SEC_NUM 6
#define STC_TM_S_YEAR 1900
#define MIN_TM_LEN 14

// Maximum recursion depth limit
#define MAX_RECU_DP 100
struct FieldLocation {
    const char *fileName;
    int lineNum;
    int fieldNum;
    const char *sep;
};
/**
 * GetCurSec - returns the current time as the number of seconds
 * since the Epoch, 1970 - 01 - 01 00:00:00 + 0000 (UTC).
 */
time_t GetCurSec(void);

/**
 * Return the current time string in the specified format
 */
const char *GetCurFmtTmStr(const char *fmt, char *strTime, int bufLen);

/**
 * GetCurFullTime - return current time as "%Y - %m - %d %H:%M:%S.mss"
 */
const char *GetCurFullTime(char *fullTime, int bufLen);

long GetTimeDistance(struct timeval v1, struct timeval v2);


/**
 * Return file size
 *
 * Note: Return zero if it fails
 */
size_t GetFileSize(const char *fileName);

/**
 * Return file lines
 *
 * Note: Return zero if it successes
 */
int GetFileLines(const char *file, int *num);

/**
 * StrTime2Sec - Convert strTime with format(20201206134723) to seconds
 */
time_t StrTime2Sec(const char *strTime);
/*
 * GetLastDaySec - Get the last second of the day
 * @day: YYYYMMDD
 */
time_t GetLastDaySec(const char *day);

/*
 * GetLastDaySec - Get the last second of the current day
 */
time_t GetLastCurDaySec(void);
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
const char *GetNthField(const char *src, const char *sep, int nth, char *pField, size_t bufLen);

/**
 * GetNthLine - Get the @nth line string of the file
 *
 * Note : return line if success; NULL if failed;
 */
const char *GetNthLine(const char *fileName, int nth, char *lineBuf, size_t bufLen);
/**
 * GetVal - Get the value of the @fieldNum'th field in the @lineNum'th line of the file
 */

const char *GetVal(struct FieldLocation fdLt, char *valBuf, size_t bufLen);

int GetValAsInt(const char *fileName, int lineNum, int fieldNum, const char *sep);
uint64_t GetValAsULong(const char *fileName, int lineNum, int fieldNum, const char *sep);
float GetValAsFloat(const char *fileName, int lineNum, int fieldNum, const char *sep);

#define ALLOC_AND_INIT_ZERO(varname, type) \
    do {                                   \
        (varname) = malloc(sizeof(type));  \
        bzero((varname), sizeof(type));    \
    } while (0)

/**
 * RemoveDir - Delete directory
 * @depth: recursion depth
 */
int RemoveDir(const char *dirName, int depth);

/**
 * NormalDirFiler - General directory filter
 */
int NormalDirFiler(const struct dirent *item);

/**
 * GetMatchN - Get the Nth matching line in the file
 *
 * Note: return match line if success; NULL on error
 * Non - thread - safe functions
 *
 */
const char *GetMatchN(const char *fileName, regex_t *pRegex, int n, char *row, int bufLen);

/**
 * MatchCnt - Returns the number of lines matching
 * the regular expression @pRegex in the file content
 * Note: return leas than zero on error
 */
int MatchCnt(const char *fileName, regex_t *pRegex);

// Create a multi - level directory
int MkDirs(const char *sDirName);

/**
 * Crc32 - Return CRC check code
 *
 * Note: return value need XOR operation with CRC_FACTOR
 */
unsigned int Crc32(unsigned int crc, const void *buffer, unsigned int size);
unsigned int GetCrc32Val(const void *buffer, unsigned int bufSize);
int GetFileCrc32Val(const char *fileName, unsigned int *fileCrc);

/*
 * IsNumStr - Check if the string is a numeric string
 * Note: return 1 for sure
 */
int IsNumStr(const char *pStr);
int NumRangeChk(const char *pStr, long min, long max);
int IsPathOk(const char *path);
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

const char *ReadNums(const char *pSrc, const char *sep, int maxCnt, uint64_t dts[], int *pArrLen);

char *Rtrim(char *str);

/*
 * StrSplit - Split string by delimiter
 *
 * IN:
 * @src Source string
 * @sep Delimiter string
 * @res Array of string pointers to hold split entries
 * @itemNum the len of @res
 *
 * OUT:
 * @res Array of string pointers to hold split entries
 * @itemNum the real count of splited entries
 *
 * RETURNS: On success, return cache pointer, the cache is used to save split entries,
 * and needs to be released after the split array is used.
 * NULL on errors;
 */
char *StrSplit(const char *src, const char *sep, char **res, int *itemNum);
/*
 * StrJoin - Use concatenations to connect string array entries
 *
 * IN:
 * @strArr String array
 * @itemNm string entries
 * @jionStr Connection string
 * @buf String pointer to save the result
 * @bufLen string buffer length
 *
 * RETURNS: pointer point to buf on success; NULL on errors
 */
const char *StrJoin(char **strArr, int itemNum, const char *joinStr, char *buf, int bufLen);
/*
 * StrReplace - Replace successive occurrences of @old in the string with a @new
 *
 * IN:
 * @src Source string
 * @dest result string point
 * @destLen result buffer length
 *
 * RETURNS: Pointer point to dest on success; NULL on errors
 */
const char *StrReplace(const char *src, const char *old, const char *new, char *dest, int destLen);
#endif
