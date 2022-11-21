/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luocaimin
 * Create: 2022-08-26
 * Description: provide cpu collect methods
 ******************************************************************************/
#ifndef GATHER_H__
#define GATHER_H__

#include <list.h>
#include <common.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#define BASE_PAY_LOAD 10000
#define NORMAL_PAY_LOAD 100
typedef struct CollVal {
    time_t collSec;
    const char* pVal;
} CollVal;

// Collect method type
typedef CollVal (* CollHandler)(void*);

// Collect config item
struct CollCfg {
    uint16_t interSec; // The number of seconds between the collection of the collector
    char mntPoint[MAX_FILE_NAME];
};

// Time keeper
struct TimeKeeper {
    int16_t leftSecs; // Seconds to next acquisition
    int16_t period; // Data Sampling period
    CollHandler handler; // Collection function
    char dataName[MAX_NAME]; // Collection item name
    struct ListHead node;
    long reserv; // Reserved field
    unsigned long long reserv1; // Reserved field
};

// Acquisition timer
struct TypeKeepers {
    struct ListHead node;
    struct ListHead tmKprLst;
    char typeName[MAX_SEC_NAME];
};

// Collection item configuration
struct CollDataCfg {
    uint16_t period;
    CollHandler handler;
    char dataName[MAX_NAME];
    char typeName[MAX_SEC_NAME];
};
// Payload struction define
typedef struct TypePayload {
    char* typeName;
    long payload;
    struct ListHead node;
} TypePayload;

typedef struct PayloadTab {
    uint16_t basePeriod;
    long totalPayload;
    struct ListHead typePayloadLst;
} PayloadTab;

typedef struct PriodCnt {
    uint16_t period;
    uint16_t cnt;
    struct ListHead node;
} PriodCnt;

typedef struct Tid {
    pthread_t tid;
    struct ListHead node;
} Tid;

typedef enum ExistSt (*ExistFuncType)(const char*);

typedef struct ExistFuncMap {
    const char* pMapNm;
    ExistFuncType handler;
} ExistFuncMap;
/**
 * InitCollector - According to the collection configuration,
 * initialize the collector
 *
 * Note: return 0 if success; -1 if failed
 */
int InitCollector(const struct CollCfg cfg);

/**
 * UpdColCfg - Update the acquisition configuration and make it effective
 */
int UpdColCfg(const struct CollCfg cfg);
/**
 * UpdPeriod - Update data collection cycle and make it effective
 *
 * @pTpNm: Pointer to the name of the collection type
 * @dNm: Pointer to the name of the collected data
 * @period: New acquisition cycle
 *
 * Note: return 0 if success; - 1 if failed
 */
int UpdPeriod(const char* pTpNm, const char* dNm, uint16_t period);
/**
 * DtCollReg - Data collection registration
 *
 * Note: return 0 if success; - 1 if failed
 */
int DtCollReg(const struct CollDataCfg* pItem);
/*
 * MapItmNm: Construct the collection item name according to
 *           the mapping rulonstruct the collection item name
 *           according to the mapping rule
 *
 * IN:
 * @name Mapping item name
 * @val Mapped name
 *
 * RETURNS: 0 on success, -1 on other
 *
 */
char* MapItmNm(const char *oldName, char *newName, int nameLen);
/**
 * DoCollect - Collect each type of data according to the collection interval,
 * summarize the collection result set, and entrust the persistence
 * module for persistence
 */
void DoCollect(void);

int StartCollector(void);

int StopCollector(void);

int RestartCollector(void);
/*
 * ClearCollector - Clean up the collector
 *
 * Note: return 0 if success; - 1 if failed
 **/
int ClearCollector(void);
/*
 * IsObjExisted - Determine whether the collection object exists
 *
 * IN:
 * @mapNm Collection object type identification string(eg: io.disk0 net.eth1...)
 * @itmNm Collection object name(eg: vda eth0 ...)
 *
 * RETURNS: EXIST or NOT_EXIST
 *
 */
enum ExistSt IsObjExisted(const char* mapNm, const char* itemNm);
#endif
