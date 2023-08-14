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
 * Description: The return code difinition of PowerAPI
 * **************************************************************************** */
#ifndef POWERAPI_ERR_H__
#define POWERAPI_ERR_H__

#define PWR_TRUE 1
#define PWR_FALSE 0

enum PWR_RtnCode {
    PWR_SUCCESS = 0,
    PWR_ERR_COMMON = 1,
    PWR_ERR_TIMEOUT,
    PWR_ERR_SYS_EXCEPTION,
    PWR_ERR_NULL_POINTER,
    PWR_ERR_INPUT_OVERSIZE,
    PWR_ERR_INVALIDE_PARAM,
    PWR_ERR_INVALIDE_DATATYPE,
    PWR_ERR_POLICY_INVALIDE,
    PWR_ERR_GOVERNOR_INVALIDE,
    PWR_ERR_FREQ_NOT_IN_RANGE,
    PWR_ERR_CALLBACK_FUNCTION_SHOULD_BE_SET_FIRST,
    PWR_ERR_MODIFY_BAN_UPDATE_ATTR_CURRENTLY,
    PWR_ERR_PATH_NORMALIZE,
    PWR_ERR_PATH_VERIFY,
    PWR_ERR_NOT_REGISTED = 100,
    PWR_ERR_NOT_AUTHED,
    PWR_ERR_OVER_MAX_CONNECTION,
    PWR_ERR_DISCONNECTED = 300,
    PWR_ERR_WRONG_RESPONSE_FROM_SERVER,
    PWR_ERR_ANSWER_LONGER_THAN_SIZE,
    PWR_ERR_CREATE_TASK_FAILED = 400,
    PWR_ERR_TASK_NOT_EXISTS,
    PWR_ERR_OVER_MAX_TASK_NUM,
    PWR_ERR_CONTROL_AUTH_REQUESTED,
    PWR_ERR_CONTROL_AUTH_OWNERED_BY_OTHERS,
    PWR_ERR_CONTROL_AUTH_NO_PERMISSION,
    PWR_ERR_FILE_ACCESS_FAILED = 500,
    PWR_ERR_FILE_FPRINT_FAILED,
    PWR_ERR_FILE_FFLUSH_FAILED,
    PWR_ERR_FILE_FOPEN_FAILED,
    PWR_ERR_FILE_SPRINTF_FIILED,
};
#endif