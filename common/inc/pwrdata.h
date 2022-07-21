/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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
 * Description: The structures definition of powerAPI.
 * **************************************************************************** */
#ifndef __POWERAPI_DATA_H__
#define __POWERAPI_DATA_H__

#define MAX_NAME_LEN 128
#define MAX_CPU_LIST_LEN 256
#define MAX_NUMA_NODE_NUM 16

typedef struct PWR_CPU_NumaInfo{
    int nodeNo;
    char cpuList[MAX_CPU_LIST_LEN];
} PWR_CPU_NumaInfo;

typedef struct PWR_CPU_Info{
    int arch;
    int byteOrder;
    char modelName[MAX_NAME_LEN];
    int coreNum;
    char onlineList[MAX_CPU_LIST_LEN];
    int threadsPerCore;
    int coresperSocket;
    double maxFreq;
    double minFreq;
    int numaNum;
    PWR_CPU_NumaInfo numa[MAX_NUMA_NODE_NUM];
} PWR_CPU_Info;


typedef struct CPUUsage {
    // todo complete CPUUsage definition
    int usage;
} CPUUsage;

#endif
