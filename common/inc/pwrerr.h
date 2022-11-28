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

#define TRUE 1
#define FALSE 0

enum RtnCode {
    SUCCESS = 0,
    ERR_COMMON = 1,
    ERR_TIMEOUT,
    ERR_SYS_EXCEPTION,
    ERR_NULL_POINTER,
    ERR_INVALIDE_PARAM,
    ERR_INVALIDE_DATATYPE,
    ERR_POLICY_INVALIDE,
    ERR_FREQ_NOT_IN_RANGE,
    ERR_CALLBACK_FUNCTION_SHOULD_BE_SET_FIRST,
    ERR_NOT_REGISTED = 100,
    ERR_NOT_AUTHED,
    ERR_OVER_MAX_CONNECTION,
    ERR_DISCONNECTED = 300,
    ERR_WRONG_RESPONSE_FROM_SERVER,
    ERR_ANSWER_LONGER_THAN_SIZE,
    ERR_CREATE_TASK_FAILED = 400,
    ERR_TASK_NOT_EXISTS,
    ERR_OVER_MAX_TASK_NUM,
    ERR_CONTROL_AUTH_REQUESTED,
    ERR_CONTROL_AUTH_OWNERED_BY_OTHERS
};
#endif
