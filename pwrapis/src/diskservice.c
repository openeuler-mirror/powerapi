/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022 All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: chengong
 * Create: 2022-08-22
 * Description: provide disk service
 * **************************************************************************** */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include "gather.h"
#include "string.h"
#include "utils.h"
#include "pwrerr.h"
#include "server.h"
#include "pwrdata.h"
#include "log.h"
#include "diskservice.h"

// Regular expression definition for matching handler
static regex_t g_rrqmRegx;
static regex_t g_wrqmRegx;
static regex_t g_rRegx;
static regex_t g_wRegx;
static regex_t g_rkbRegx;
static regex_t g_wkbRegx;
static regex_t g_avgrgszRegx;
static regex_t g_avgquszRegx;
static regex_t g_svctmRegx;
static regex_t g_utilRegx;
static regex_t g_awaitRegx;
static struct ListHead hanlerMap;

typedef struct IoHdRef {
    regex_t* regx;
    CollHandler pHanler;
} IoHdRef;

static const char* GetStatInfo(const char* diskName, char statLine[], int bufLen)
{
    int res;
    int majorNum;
    int minorNum;
    regex_t prxRgx;
    struct stat st;
    char strPrxRgx[MAX_LINE_LENGTH] = {0};
    char devFlNm[MAX_FILE_NAME] = {0};
    const char* pRes = NULL;
    const char* statFile = "/proc/diskstats";

    if (sprintf(devFlNm, "/dev/%s", diskName) < 0) {
        return NULL;
    }

    if (stat(devFlNm, &st) != 0) {
        return NULL;
    }
    majorNum = major(st.st_rdev);
    minorNum = minor(st.st_rdev);
    // match format " major minor diskName"
    if (sprintf(strPrxRgx, "^\\s+%d\\s+%d\\s+%s", majorNum, minorNum, diskName) < 0) {
        return NULL;
    }
    regcomp(&prxRgx, strPrxRgx, REG_EXTENDED | REG_NOSUB);
    pRes = GetMatchN(statFile, &prxRgx, 1, statLine, bufLen);
    regfree(&prxRgx);
    return pRes;
}

/*
 * GetDskNm - Get disk name from data name which with format[eg: io.sda.rrqm]
 * Return disk name on success, NULL otherwise
 */
static const char* GetDskNm(const char* pDataNm, char* dskName, int bufLen)
{
    return GetNthField(pDataNm, DT_NM_SEP_STR, FD_NUM_DSK_NM, dskName, bufLen);
}

enum ExistSt IsDskExisted(const char* dskNm)
{
    const char* pStrRes = NULL;
    char line[MAX_LINE_LENGTH] = {0};

    pStrRes = GetStatInfo(dskNm, line, sizeof(line) - 1);
    if (pStrRes != NULL) {
        return EXIST;
    }
    return NOT_EXIST;
}

static enum ExistSt IsDtDskExisted(const char* pDataNm)
{
    const char* pStrRes = NULL;
    char dskNm[MAX_DSK_NM_LEN] = {0};

    pStrRes = GetDskNm(pDataNm, dskNm, sizeof(dskNm) - 1);
    if (pStrRes == NULL) {
        return NOT_EXIST;
    }
    return IsDskExisted(dskNm);
}

static int64_t GetStatField(const char* statLine, uint16_t fieldIdx)
{
    int64_t fdVal;
    const char* pRes = NULL;
    char statVal[STR_LEN_FOR_LONG] = {0};
    pRes = GetNthField(statLine, " \n", fieldIdx, statVal, sizeof(statVal) - 1);
    if (pRes == NULL) {
        return -1;
    }
    fdVal = -1;
    if (sscanf(statVal, "%lu", &fdVal) < 0) {
        return -1;
    }
    return fdVal;
}

static int64_t GetFdVal(const char* dataName, int fdIdx)
{
    const char* pRes = NULL;
    char dskNm[MAX_DSK_NM_LEN] = {0};
    char line[MAX_LINE_LENGTH] = {0};

    pRes = GetDskNm(dataName, dskNm, sizeof(dskNm) - 1);
    if (pRes == NULL) {
        return ERR_NULL_POINTER;
    }
    pRes = GetStatInfo(dskNm, line, sizeof(line) - 1);
    if (pRes == NULL) {
        return ERR_NULL_POINTER;
    }
    return GetStatField(line, fdIdx);
}

static float GetValPerSec(struct TimeKeeper* pTmKp, int fieldNum, float divFctr)
{
    float resVal;
    float period;
    int64_t fieldVal;

    period = pTmKp->period;
    // Get field value
    fieldVal = GetFdVal(pTmKp->dataName, fieldNum);
    // Average per second in period
    resVal = (fieldVal - pTmKp->reserv) / period;
    pTmKp->reserv = fieldVal;
    return resVal / divFctr;
}

static CollVal ValPerSec(struct TimeKeeper* pTmKp, int fieldNum, float divFctr)
{
    float resVal;
    CollVal colVal;
    static char strVal[MAX_VALUE] = {0};

    colVal.collSec = 0;
    resVal = GetValPerSec(pTmKp, fieldNum, divFctr);
    if (sprintf(strVal, "%.2f", resVal) < 0) {
        colVal.pVal = ERR_VAL;
    } else {
        colVal.pVal = strVal;
    }
    return colVal;
}

static CollVal DiskRrqm(void* args)
{
    return ValPerSec(args, RG_MEGR_FD_NUM, 1);
}

static CollVal DiskWrqm(void* args)
{
    return ValPerSec(args, WG_MEGR_FD_NUM, 1);
}

static CollVal DiskRs(void* args)
{
    return ValPerSec(args, R_MEGR_FD_NUM, 1);
}

static CollVal DiskWs(void* args)
{
    return ValPerSec(args, W_MEGR_FD_NUM, 1);
}

static CollVal DiskRkb(void* args)
{
    return ValPerSec(args, RKB_FD_NUM, SECTOR_TO_KB_FACTOR);
}

static CollVal DiskWkb(void* args)
{
    return ValPerSec(args, WKB_FD_NUM, SECTOR_TO_KB_FACTOR);
}

/*
 * ******************************************
 * GetIos - Read/write/deleted io requests in query statistics
 *
 * IN:
 * @dataName Collected data name
 *
 * RETURNS:
 * Ios
 * ******************************************
 */
static Ios GetIos(const char* dataName)
{
    Ios ios;

    ios.rdIos = GetFdVal(dataName, R_MEGR_FD_NUM);
    ios.wrIos = GetFdVal(dataName, W_MEGR_FD_NUM);
    ios.dcIos = GetFdVal(dataName, DC_IOS_FD_NUM);
    ios.dcIos = ios.dcIos < 0 ? 0 : ios.dcIos;
    return ios;
}

/*
 * ******************************************
 * GetSectors - Read/write/deleted sectors in statistics
 *
 * IN:
 * @dataName Collected data name
 *
 * RETURNS:
 * Sectors
 * ******************************************
 */
static Sectors GetSectors(const char* dataName)
{
    Sectors sectors;

    sectors.rdSect = GetFdVal(dataName, RKB_FD_NUM);
    sectors.wrSect = GetFdVal(dataName, WKB_FD_NUM);
    sectors.dcSect = GetFdVal(dataName, DC_SECT_FD_NUM);
    sectors.dcSect = sectors.dcSect < 0 ? 0 : sectors.dcSect;
    return sectors;
}

static CollVal DiskAvgRgSz(void* args)
{
    float val;
    Ios ios;
    Sectors sectors;
    uint64_t curSumSectors;
    uint64_t curSumRstCnt;
    CollVal collVal;
    struct TimeKeeper* pTmKp = NULL;
    static char strVal[MAX_VALUE] = {0};

    pTmKp = args;
    ios = GetIos(pTmKp->dataName);
    sectors = GetSectors(pTmKp->dataName);
    curSumRstCnt = ios.rdIos + ios.wrIos + ios.dcIos;
    curSumSectors = sectors.rdSect + sectors.wrSect + sectors.dcSect;
    if ((curSumRstCnt - pTmKp->reserv1) == 0) {
        val = 0.0;
    } else {
        val = (curSumSectors - pTmKp->reserv) / (double)(curSumRstCnt - pTmKp->reserv1) / AVGSZ_FACTOR;
    }
    pTmKp->reserv = curSumSectors;
    pTmKp->reserv1 = curSumRstCnt;
    collVal.collSec = 0;
    if (sprintf(strVal, "%.2f", val) < 0) {
        collVal.pVal = ERR_VAL;
    } else {
        collVal.pVal = strVal;
    }
    return collVal;
}

static CollVal DiskAvgQuSz(void* args)
{
    return ValPerSec(args, RQ_TK_FD_NUM, QUSZ_FACTOR);
}

static CollVal DiskSvctm(void* args)
{
    uint64_t util;
    CollVal colVal;
    uint64_t tmpRws;
    Ios tmpIos;
    float svctm;
    struct TimeKeeper* pTmKp = NULL;
    static char strVal[MAX_VALUE] = {0};

    pTmKp = args;
    util = GetFdVal(pTmKp->dataName, TOL_TK_FD_NUM);
    tmpIos = GetIos(pTmKp->dataName);
    tmpRws = tmpIos.rdIos + tmpIos.wrIos;
    if ((tmpRws - pTmKp->reserv1) > 0) {
        svctm = (util - pTmKp->reserv) / (tmpRws - pTmKp->reserv1);
    } else {
        svctm = 0.0;
    }
    pTmKp->reserv = util;
    pTmKp->reserv1 = tmpRws;
    if (sprintf(strVal, "%.2f", svctm) < 0) {
        colVal.pVal = ERR_VAL;
    } else {
        colVal.pVal = strVal;
    }
    colVal.collSec = 0;
    return colVal;
}

static CollVal DiskUtil(void* args)
{
    float resVal;
    CollVal colVal;
    static char strVal[MAX_VALUE] = {0};
    struct TimeKeeper* pTmKp = NULL;

    pTmKp = args;
    colVal.collSec = 0;
    resVal = GetValPerSec(args, TOL_TK_FD_NUM, UTIL_FACTOR);
    if (sprintf(strVal, "%.5f", resVal) < 0) {
        colVal.pVal = ERR_VAL;
    } else {
        colVal.pVal = strVal;
    }
    return colVal;
}

/*
 * ******************************************
 * GetTicks - Read/write/deleted tickes in statistics
 *
 * IN:
 * @dataName Collected data name
 *
 * RETURNS:
 * Ticks
 * ******************************************
 */
static Ticks GetTicks(const char* dataName)
{
    Ticks ticks;
    ticks.rdTicks = GetFdVal(dataName, RD_TICKS_FD_NUM);
    ticks.wrTicks = GetFdVal(dataName, WR_TICKS_FD_NUM);
    ticks.dcTicks = GetFdVal(dataName, DC_TICKS_FD_NUM);
    ticks.dcTicks = ticks.dcTicks < 0 ? 0 : ticks.dcTicks;
    return ticks;
}

typedef struct AwaitFactor {
    int64_t preSumTicks;
    uint64_t preSumRstCnt;
} AwaitFactor;

static CollVal DiskAwait(void* args)
{
    Ios ios;
    float val;
    Ticks ticks;
    CollVal collVal;
    uint64_t curSumRstCnt;
    uint64_t curSumTicks;
    static char strVal[MAX_VALUE] = {0};
    struct TimeKeeper* pTmKp = NULL;

    pTmKp = args;
    ios = GetIos(pTmKp->dataName);
    curSumRstCnt = ios.rdIos + ios.wrIos + ios.dcIos;
    ticks = GetTicks(pTmKp->dataName);
    curSumTicks = ticks.rdTicks + ticks.wrTicks + ticks.dcTicks;
    if ((curSumRstCnt - pTmKp->reserv) == 0) {
        val = 0.0;
    } else {
        val = (curSumTicks - pTmKp->reserv1) / (double)(curSumRstCnt - pTmKp->reserv);
    }
    pTmKp->reserv = curSumRstCnt;
    pTmKp->reserv1 = curSumTicks;
    if (sprintf(strVal, "%.2f", val) < 0) {
        collVal.pVal = ERR_VAL;
    } else {
        collVal.pVal = strVal;
    }
    collVal.collSec = 0;
    return collVal;
}

static void InitRegx(void)
{
    char *strReg;

    strReg = "^io.(\\w|_|-)+.rrqm$";
    regcomp(&g_rrqmRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.wrqm$";
    regcomp(&g_wrqmRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.r$";
    regcomp(&g_rRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.w$";
    regcomp(&g_wRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.rkB$";
    regcomp(&g_rkbRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.wkB$";
    regcomp(&g_wkbRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.avgrg-sz$";
    regcomp(&g_avgrgszRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.avgqu-sz$";
    regcomp(&g_avgquszRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.svctm$";
    regcomp(&g_svctmRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.util$";
    regcomp(&g_utilRegx, strReg, REG_EXTENDED | REG_NOSUB);
    strReg = "^io.(\\w|_|-)+.await$";
    regcomp(&g_awaitRegx, strReg, REG_EXTENDED | REG_NOSUB);
}

IoHdRef hdArr[] = {
    { &g_rrqmRegx, DiskRrqm },
    { &g_wrqmRegx, DiskWrqm },
    { &g_rRegx, DiskRs},
    { &g_wRegx, DiskWs},
    { &g_rkbRegx, DiskRkb},
    { &g_wkbRegx, DiskWkb},
    { &g_avgrgszRegx, DiskAvgRgSz},
    { &g_avgquszRegx, DiskAvgQuSz},
    { &g_svctmRegx, DiskSvctm},
    { &g_utilRegx, DiskUtil},
    { &g_awaitRegx, DiskAwait},
};

static CollHandler GetColHdl(const char* dataName)
{
    int idx;
    size_t len;

    len = sizeof(hdArr) / sizeof(IoHdRef);
    for (idx = 0; idx < len; ++idx) {
        if (regexec(hdArr[idx].regx, dataName, 0, NULL, 0) == 0) {
            return hdArr[idx].pHanler;
        }
    }
    return NULL;
}

static void DskRgst(const struct ListHead* pCollCfg)
{
    int period = 0;
    CollHandler tmpHdl;
    struct ListHead* pos = NULL;
    struct CnfItem* pItem = NULL;
    struct CollDataCfg collCfg;

    bzero(&collCfg, sizeof(collCfg));

    strcpy(collCfg.typeName, "io");

    LIST_FOR_EACH(pos, pCollCfg) {
        pItem = GET_LIST_ITEM(pos, struct CnfItem, node);
        tmpHdl = GetColHdl(pItem->name);
        if (tmpHdl == NULL) {
            continue;
        }
        if (IsDtDskExisted(pItem->name) == 0) {
            Logger(WARNING, MD_NM_GTH, "%s [%s] relate disk not existed, ignore!", __FUNCTION__, pItem->name);
            continue;
        }
        strncpy(collCfg.dataName, pItem->name, sizeof(collCfg.dataName) - 1);
        collCfg.handler = tmpHdl;
        if (sscanf(pItem->value, "%d", &period) < 0) {
            continue;
        }
        collCfg.period = period;
        /* register io data collection to "gather" module */
        // DtCollReg(&collCfg);
    }
}

void InitIoColl(void)
{
    InitRegx();
}

void ClearIoColl(void)
{
    int i;
    size_t length;

    length = sizeof(hdArr) / sizeof(IoHdRef);
    for (i = 0; i < length; ++i) {
        regfree(hdArr[i].regx);
    }
}

int RegIoColl(const struct ListHead* pCollCfg)
{
    if (pCollCfg == NULL) {
        return ERR_NULL_POINTER;
    }
    DskRgst(pCollCfg);
    return SUCCESS;
}

int ReadDiskName(const char *file, PWR_DISK_Info disklist[], int diskNum)
{
    int i;
    int DiskNamePos = 3; // file /proc/diskstats format: major minor diskname xxx xxx
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    const char* pRes = NULL;
    char statVal[MAX_ELEMENT_NAME_LEN] = {0};

    if (file == NULL) {
        return ERR_INVALIDE_PARAM;
    }
    if (access(file, F_OK | R_OK) != 0) {
        return ERR_COMMON;
    }

    fp = fopen(file, "r");
    if (fp == NULL) {
        return ERR_NULL_POINTER;
    }

    for (i = 0; i < diskNum; i++) {
        while ((read = getline(&line, &len, fp)) != -1) {
            pRes = GetNthField(line, " \n", DiskNamePos, statVal, sizeof(statVal) - 1);
            if (pRes != NULL) {
                strncpy(disklist[i].diskId, statVal, strlen(statVal));
            } else {
                disklist[i].diskId[0] = '\0';
            }
        }
    }

    if (line) {
        free(line);
    }
    if (fclose(fp) < 0) {
        return ERR_COMMON;
    }
    return SUCCESS;
}

void GetDiskinfo(PwrMsg *req)
{
    const char* statFile = "/proc/diskstats";
    if (!req) {
        return;
    }
    Logger(DEBUG, MD_NM_SVR_DISK, "Get DISK info Req. seqId:%u, sysId:%d", req->head.seqId, req->head.sysId);
    int diskNum;
    GetFileLines(statFile, &diskNum);
    PWR_DISK_Info *rstData = malloc(sizeof(PWR_DISK_Info) * diskNum);
    if (!rstData) {
        return;
    }
    int rspCode = ReadDiskName(statFile, rstData, diskNum);
    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR_DISK, "Malloc failed.");
        free(rstData);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, (char *)rstData, sizeof(PWR_DISK_Info) * diskNum);
    if (SendRspMsg(rsp) != SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}

void GetDiskLoad(PwrMsg *req)
{
}

void GetDiskPowerStatus(PwrMsg *req)
{
}

void SetDiskPowerStatus(PwrMsg *req)
{
}

void GetDiskScsiPolicy(PwrMsg *req)
{
}

void SetDiskScsiPolicy(PwrMsg *req)
{
}
