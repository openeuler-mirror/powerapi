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
 * Description: Provide IPC ability. Socket initialization, send/receive msg, send/recieve buffer
 * **************************************************************************** */

#include "sockclient.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <regex.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "pwrbuffer.h"

#define CLIENT_ADDR "pwrclient.sock"
#define INVALID_FD (-1)
#define SOCK_THREAD_LOOP_INTERVAL 2000 // us
#define RECONNECTE_INTERVAL 3          // s
#define MAX_PID_LEN 12
#define MAX_PROC_NUM_IN_ONE_LOOP 5
#define MAX_PATH_LEN 128

static int g_sockFd = INVALID_FD;
static ThreadInfo g_sockThread;

static PwrMsgBuffer g_sendBuff;         // Send queue
static PwrMsgBuffer g_recvBuff;         // Receive queue
static ResultWaitingMsgList g_waitList; // Waiting for results list
static char g_serverAddr[MAX_PATH_LEN] = "/etc/sysconfig/pwrapis/pwrserver.sock"; // Default server path
static char cus_clientAddr[MAX_PATH_LEN] = ""; // User defined client path
static PwrApiStatus g_status = STATUS_UNREGISTERED;

#define CHECK_SOCKET_STATUS()                         \
    if (g_sockFd == INVALID_FD) {                     \
        PwrLog(ERROR, "check socket status failed."); \
        return PWR_ERR_DISCONNECTED;                      \
    }

static char* GetClientSockDir(char *dir, char *cus_dir)
{
    char *prefix;
    if (strlen(cus_dir) > 0) {
        prefix = cus_dir;
    } else {
        prefix = getenv("HOME");
    }
    if (!prefix || sprintf(dir, "%s/%s", prefix, CLIENT_ADDR) < 0) {
        PwrLog(ERROR, "Get Client home dir failed.");
    }
    return dir;
}

static int ReadMsg(void *pData, int len)
{
    int leftLen;
    int recvLen;
    int readLen = 0;

    leftLen = len;
    while (leftLen > 0) {
        recvLen = recv(g_sockFd, pData + readLen, leftLen, 0);
        if (recvLen < 0) {
            PwrLog(ERROR, "Recv error %s errno: %d", strerror(errno), errno);
            close(g_sockFd);
            g_sockFd = INVALID_FD;
            return PWR_ERR_SYS_EXCEPTION;
        } else if (recvLen == 0) {
            PwrLog(ERROR, "Connection closed !");
            g_sockFd = INVALID_FD;
            return PWR_ERR_DISCONNECTED;
        }
        readLen += recvLen;
        leftLen -= recvLen;
    }
    return PWR_SUCCESS;
}

static int WriteMsg(const void *pData, size_t len)
{
    size_t leftLen;
    ssize_t sendLen;
    size_t wrLen = 0;

    leftLen = len;
    while (leftLen > 0) {
        sendLen = send(g_sockFd, pData + wrLen, leftLen, 0);
        if (sendLen < 0) {
            PwrLog(ERROR, "Send error %s errno: %d", strerror(errno), errno);
            close(g_sockFd);
            g_sockFd = INVALID_FD;
            return PWR_ERR_SYS_EXCEPTION;
        }
        leftLen -= sendLen;
        wrLen += sendLen;
    }
    return PWR_SUCCESS;
}

static void (*g_metadata_callback)(const PWR_COM_CallbackData *) = NULL;
static void DoDataCallback(PwrMsg *msg)
{
    if (msg->head.dataLen < sizeof(PWR_COM_CallbackData)) {
        PwrLog(DEBUG, "DoDataCallback. msg data len error. len: %d", msg->head.dataLen);
        ReleasePwrMsg(&msg);
        return;
    }
    PWR_COM_CallbackData *callBackData = (PWR_COM_CallbackData *)msg->data;
    if (callBackData->dataLen <= 0) {
        PwrLog(DEBUG, "DoDataCallback. data empty. len: %d", callBackData->dataLen);
        ReleasePwrMsg(&msg);
        return;
    }
    if (g_metadata_callback == NULL) {
        PwrLog(ERROR, "No metadata callback.");
        ReleasePwrMsg(&msg);
        return;
    }
    g_metadata_callback(callBackData);
    ReleasePwrMsg(&msg);
}

static int EventPreProcessing(const PWR_COM_EventInfo *event)
{
    switch (event->eventType) {
        case PWR_COM_EVTTYPE_AUTH_RELEASED:
            SetPwrApiStatus(STATUS_REGISTERTED);
            break;
        default:
            break;
    }
    return PWR_SUCCESS;
}

static void DefaultEventCallback(const PWR_COM_EventInfo *eventInfo)
{
    printf("[Event] ctime:%s, type:%d, info:%s\n", eventInfo->ctime,
        eventInfo->eventType, eventInfo->info);
}

static void (*g_event_callback)(const PWR_COM_EventInfo *) = DefaultEventCallback;
static void DoEventCallback(PwrMsg *msg)
{
    if (msg->head.dataLen < sizeof(PWR_COM_EventInfo)) {
        PwrLog(DEBUG, "DoEventCallback. msg data len error. len: %d", msg->head.dataLen);
        ReleasePwrMsg(&msg);
        return;
    }
    PWR_COM_EventInfo *callbackEvent = (PWR_COM_EventInfo *)msg->data;
    (void)EventPreProcessing(callbackEvent);

    if (g_event_callback == NULL) {
        PwrLog(ERROR, "No event callback function.");
        ReleasePwrMsg(&msg);
        return;
    }
    g_event_callback(callbackEvent);
    ReleasePwrMsg(&msg);
}

static void ProcessRspMsg(PwrMsg *rsp)
{
    ResultWaitingMsgNode *rwm = FindAndMoveWaitingMsg(&g_waitList, rsp->head.seqId);
    if (!rwm) {
        ReleasePwrMsg(&rsp);
        return; // drop this msg
    }
    rwm->rspMsg = rsp;
    if (DoRspToWaitingMsg(rwm) != PWR_SUCCESS) {
        ReleasePwrMsg(&rsp);
        return;
    }
}
static void ProcessEvtMsg(PwrMsg *msg)
{
    switch (msg->head.optType) {
        case COM_CALLBACK_EVENT:
            DoEventCallback(msg);
            break;
        default:
            ReleasePwrMsg(&msg);
            break;
    }
}
static void ProcessOtherMsg(PwrMsg *msg)
{
    /* if (AddToBufferTail(&g_recvBuff, msg) != PWR_SUCCESS) {
        ReleasePwrMsg(&msg);
    } */
    switch (msg->head.optType) {
        case COM_CALLBACK_DATA:
            DoDataCallback(msg);
            break;
        default:
            ReleasePwrMsg(&msg);
            break;
    }
}

static void RecvMsgFromSocket(void)
{
    PwrMsg *msg = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!msg) {
        return;
    }
    bzero(msg, sizeof(PwrMsg));
    if (ReadMsg(msg, sizeof(PwrMsg)) != PWR_SUCCESS) {
        free(msg);
        return;
    }

    if (msg->head.dataLen != 0) {
        char *msgcontent = malloc(msg->head.dataLen);
        if (!msgcontent) {
            free(msg);
            return;
        }
        bzero(msgcontent, msg->head.dataLen);
        if (ReadMsg(msgcontent, msg->head.dataLen) != PWR_SUCCESS) {
            free(msg);
            free(msgcontent);
            return;
        }
        msg->data = msgcontent;
    } else {
        msg->data = NULL;
    }

    switch (msg->head.msgType) {
        case MT_RSP:
            ProcessRspMsg(msg);
            break;
        case MT_EVT:
            ProcessEvtMsg(msg);
            break;
        default:
            ProcessOtherMsg(msg);
            break;
    }
}

static void SendMsgToSocket(void)
{
    int count = 0;
    static char data[MAX_DATA_SIZE];
    while (!IsEmptyBuffer(&g_sendBuff) && count < MAX_PROC_NUM_IN_ONE_LOOP) {
        PwrMsg *msg = PopFromBufferHead(&g_sendBuff);
        count++;
        if (!msg) {
            continue;
        }
        size_t len = sizeof(PwrMsg) + msg->head.dataLen;

        if (len <= MAX_DATA_SIZE) {
            memcpy(data, msg, sizeof(PwrMsg));
            if (msg->data && msg->head.dataLen > 0) {
                memcpy(data + sizeof(PwrMsg), msg->data, msg->head.dataLen);
            }
            WriteMsg(data, len);
        } else {
            memcpy(data, msg, sizeof(PwrMsg));
            memcpy(data + sizeof(PwrMsg), msg->data, MAX_DATA_SIZE - sizeof(PwrMsg));
            WriteMsg(data, MAX_DATA_SIZE);
            size_t datasent = MAX_DATA_SIZE - sizeof(PwrMsg);
            size_t leftLen = len - MAX_DATA_SIZE;
            while (leftLen > MAX_DATA_SIZE) {
                memcpy(data, msg->data + datasent, MAX_DATA_SIZE);
                WriteMsg(data, MAX_DATA_SIZE);
                datasent += MAX_DATA_SIZE;
                leftLen -= MAX_DATA_SIZE;
            }
            memcpy(data, msg->data + datasent, leftLen);
            WriteMsg(data, leftLen);
        }
        ReleasePwrMsg(&msg);
    }
}


static int CreateConnection(void)
{
    int clientFd;
    clientFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (clientFd < 0) {
        PwrLog(ERROR, "Create socket failed. ret: %d", clientFd);
        return PWR_ERR_COMMON;
    }
    // bind
    struct sockaddr_un clientAddr;
    bzero(&clientAddr, sizeof(clientAddr));
    clientAddr.sun_family = AF_UNIX;
    char sockDir[MAX_PATH_LEN] = CLIENT_ADDR;
    strncpy(clientAddr.sun_path, GetClientSockDir(sockDir, cus_clientAddr), sizeof(clientAddr.sun_path) - 1);
    size_t clen = SUN_LEN(&clientAddr);
    unlink(clientAddr.sun_path);
    if (bind(clientFd, (struct sockaddr *)&clientAddr, clen) < 0) {
        PwrLog(ERROR, "Bind socket failed.");
        close(clientFd);
        return PWR_ERR_COMMON;
    }
    mode_t mode = 0400;
    if (chmod(clientAddr.sun_path, mode) == -1) {
        PwrLog(ERROR, "set permission error");
        return PWR_ERR_SYS_EXCEPTION;
    }
    // connect
    struct sockaddr_un serverAddr;
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sun_family = AF_UNIX;
    strncpy(serverAddr.sun_path, g_serverAddr, sizeof(serverAddr.sun_path) - 1);
    size_t slen = SUN_LEN(&serverAddr);
    if (connect(clientFd, (struct sockaddr *)&serverAddr, slen) < 0) {
        if (access(g_serverAddr, F_OK) != 0) {
            PwrLog(ERROR, "Server sock doesn't exist. Check server addr path please.");
        }
        PwrLog(ERROR, "Connect to server failed.");
        close(clientFd);
        return PWR_ERR_COMMON;
    }

    g_sockFd = clientFd;
    PwrLog(INFO, "Connect to server succeed. fd: %d", g_sockFd);
    return PWR_SUCCESS;
}

static void *RunSocketProcess(void *none)
{
    (void)none; // used to avoid unused parameter warning
    fd_set recvFdSet;
    struct timeval tv;
    while (g_sockThread.keepRunning) {
        if (g_sockFd == INVALID_FD) {
            sleep(RECONNECTE_INTERVAL);
            CreateConnection(); // resume the connection
            continue;
        }

        tv.tv_sec = 0;
        tv.tv_usec = SOCK_THREAD_LOOP_INTERVAL;
        FD_ZERO(&recvFdSet);
        FD_SET(g_sockFd, &recvFdSet);

        if (!IsEmptyBuffer(&g_sendBuff)) {
            SendMsgToSocket();
        }

        int ret = select(g_sockFd + 1, &recvFdSet, NULL, NULL, &tv);
        if (ret > 0 && FD_ISSET(g_sockFd, &recvFdSet)) {
            RecvMsgFromSocket();
        }
    } // while
    return NULL;
}


static int SendMsgSyn(PwrMsg *msg, PwrMsg **rsp)
{
    if (!msg || !rsp) {
        return PWR_ERR_NULL_POINTER;
    }
    CHECK_SOCKET_STATUS();

    // copy to sending buffer
    PwrMsg *copy = ClonePwrMsg(msg);
    if (!copy) {
        return -1;
    }
    AddToBufferTail(&g_sendBuff, copy);

    // Waiting for response
    ResultWaitingMsgNode *node = CreateResultWaitingMsgNode();
    if (!node) {
        PwrLog(ERROR, "Malloc failed.");
        ReleasePwrMsg(&msg);
        return PWR_ERR_SYS_EXCEPTION;
    }
    node->reqMsg = msg;
    AddToWaitingListTail(&g_waitList, node);
    int ret = WaitingForResponse(node);
    if (ret != PWR_SUCCESS) {
        // timeout or error scenario. the msg still waiting in the list. need to move out.
        MoveOutWaitingMsg(&g_waitList, node);
    }
    *rsp = node->rspMsg;
    node->reqMsg = NULL;
    node->rspMsg = NULL;
    ReleaseResultWaitingMsgNode(node);
    return PWR_SUCCESS;
}

static int SendReqMsgAndWaitForRsp(PwrMsg *req, PwrMsg **rsp)
{
    if (!req || !rsp) {
        return PWR_ERR_NULL_POINTER;
    }
    CHECK_SOCKET_STATUS();

    if (SendMsgSyn(req, rsp) != PWR_SUCCESS) {
        PwrLog(ERROR, "Send msg to server failed. optType: %d, seqId: %u", req->head.optType, req->head.seqId);
        return PWR_ERR_SYS_EXCEPTION;
    }

    if (*rsp == NULL || (*rsp)->head.rspCode != PWR_SUCCESS) {
        PwrLog(ERROR, "Rsp error. optType: %d, seqId: %u", req->head.optType, req->head.seqId);
        return *rsp == NULL ? PWR_ERR_COMMON : (*rsp)->head.rspCode;
    }
    return PWR_SUCCESS;
}

// public****************************************************************************************/
int SetServerInfo(const char* socketPath)
{
    strncpy(g_serverAddr, socketPath, sizeof(g_serverAddr) - 1);
    return PWR_SUCCESS;
}

int SetClientSockPath(const char* socketPath)
{
    if (access(socketPath, W_OK) != 0) {
        return PWR_ERR_PATH_VERIFY;
    }
    strncpy(cus_clientAddr, socketPath, sizeof(cus_clientAddr) - 1);
    return PWR_SUCCESS;
}

int InitSockClient(void)
{
    InitPwrMsgBuffer(&g_sendBuff);
    InitPwrMsgBuffer(&g_recvBuff);
    InitResultWaitingList(&g_waitList);
    InitMsgFactory();
    InitThreadInfo(&g_sockThread);
    int ret = PWR_SUCCESS;
    do {
        if (CreateConnection() != PWR_SUCCESS) {
            ret = PWR_ERR_COMMON;
            break;
        }
        int r = CreateThread(&g_sockThread, RunSocketProcess, NULL);
        if (r != PWR_SUCCESS) {
            PwrLog(ERROR, "Create recv thread failed. ret: %d", r);
            ret = PWR_ERR_COMMON;
            break;
        }
    } while (0);
    if (ret != PWR_SUCCESS) {
        FiniSockClient();
    }
    return ret;
}

int FiniSockClient(void)
{
    FiniThreadInfo(&g_sockThread);
    close(g_sockFd);
    g_sockFd = INVALID_FD;
    ResetPwrMsgBuffer(&g_sendBuff);
    ResetPwrMsgBuffer(&g_recvBuff);
    ResetResultWaitingList(&g_waitList);
    DestroyMsgFactory();
    return PWR_SUCCESS;
}

int SetMetaDataCallback(void(MetaDataCallback)(const PWR_COM_CallbackData *))
{
    g_metadata_callback = MetaDataCallback;
    return PWR_SUCCESS;
}

int SetEventCallback(void(EventCallback)(const PWR_COM_EventInfo *))
{
    if (EventCallback) {
        g_event_callback = EventCallback;
        return PWR_SUCCESS;
    }
    return PWR_ERR_NULL_POINTER;
}

int HasSetDataCallback(void)
{
    return g_metadata_callback != NULL;
}

int SendReqAndWaitForRsp(const ReqInputParam input, RspOutputParam output)
{
    if ((output.rspData && (!output.rspBuffSize || *output.rspBuffSize == 0))) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    char *inputData = NULL;
    if (input.data && input.dataLen != 0) {
        inputData = (char *)malloc(input.dataLen); // Be released when PwrMsg released
        bzero(inputData, input.dataLen);
        memcpy(inputData, input.data, input.dataLen);
    }

    PwrMsg *req = CreateReqMsg(input.optType, input.taskNo, input.dataLen, inputData);
    if (!req) {
        PwrLog(ERROR, "Create req msg failed. optType: %d", input.optType);
        free(inputData);
        return PWR_ERR_SYS_EXCEPTION;
    }

    PwrMsg *rsp = NULL;
    int ret = SendReqMsgAndWaitForRsp(req, &rsp);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "Send req failed. optType: %d, ret: %d", input.optType, ret);
        ReleasePwrMsg(&req);
        ReleasePwrMsg(&rsp);
        return ret;
    }

    if (output.rspData) {
        uint32_t srcSize = *output.rspBuffSize;
        if (rsp->data) {
            int dlen = srcSize < rsp->head.dataLen ? srcSize : rsp->head.dataLen;
            memcpy(output.rspData, rsp->data, dlen);
            *output.rspBuffSize = dlen;
        } else {
            ReleasePwrMsg(&req);
            ReleasePwrMsg(&rsp);
            return PWR_ERR_WRONG_RESPONSE_FROM_SERVER;
        }
    }

    PwrLog(DEBUG, "Request succeed. optType: %d", input.optType);
    ReleasePwrMsg(&req);
    ReleasePwrMsg(&rsp);
    return PWR_SUCCESS;
}

PwrApiStatus GetPwrApiStatus()
{
    return g_status;
}

int SetPwrApiStatus(PwrApiStatus status)
{
    g_status = status;
    return PWR_SUCCESS;
}
