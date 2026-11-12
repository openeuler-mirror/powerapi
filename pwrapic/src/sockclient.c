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

// Lifecycle guard: serializes Init/Fini against in-flight requests.
// Lock order: g_lifeMutex -> g_waitList.mutex -> node->waitMutex
#define FINI_DRAIN_TIME_OUT 160 // s, must exceed WAITING_RESULT_TIME_OUT(150)
static pthread_mutex_t g_lifeMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_statusMutex = PTHREAD_MUTEX_INITIALIZER; // guards g_status only
static int g_inflightReq = 0;   // requests inside SendReqAndWaitForRsp
static int g_finiing = PWR_FALSE;
static int g_sockInited = PWR_FALSE; // TRUE between successful Init and full destroy

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
    // FindAndMoveWaitingMsg hands over the rsp and marks the node finished
    // atomically under the list+node mutexes. NULL means no waiter matched
    // (already timed out or cancelled by Fini): drop the rsp here.
    ResultWaitingMsgNode *rwm = FindAndMoveWaitingMsg(&g_waitList, rsp->head.seqId, rsp);
    if (!rwm) {
        ReleasePwrMsg(&rsp);
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
    clientFd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
            pthread_mutex_lock(&g_lifeMutex);
            // Do not reconnect while the client is being destroyed
            if (!g_finiing && g_sockFd == INVALID_FD && g_sockThread.keepRunning) {
                CreateConnection(); // resume the connection
            }
            pthread_mutex_unlock(&g_lifeMutex);
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
    // Detach: remove the node from the list if the recv thread hasn't claimed
    // it yet, then re-take the node mutex before reading rspMsg. If the recv
    // thread removed it first, its claim (rsp handover + finished mark) ran
    // while holding the node mutex inside the list mutex, so this lock either
    // sees the final state or was never contended - no use-after-free window.
    (void)MoveOutWaitingMsg(&g_waitList, node);
    pthread_mutex_lock(&(node->waitMutex));
    *rsp = node->rspMsg;
    node->reqMsg = NULL;
    node->rspMsg = NULL;
    pthread_mutex_unlock(&(node->waitMutex));
    ReleaseResultWaitingMsgNode(node);
    return ret;
}

static int SendReqMsgAndWaitForRsp(PwrMsg *req, PwrMsg **rsp)
{
    if (!req || !rsp) {
        return PWR_ERR_NULL_POINTER;
    }
    CHECK_SOCKET_STATUS();

    int ret = SendMsgSyn(req, rsp);
    if (ret != PWR_SUCCESS) {
        PwrLog(ERROR, "Send msg to server failed. optType: %d, seqId: %u, ret: %d",
            req->head.optType, req->head.seqId, ret);
        return ret;
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

static int FiniSockClientInternal(void);

int InitSockClient(void)
{
    pthread_mutex_lock(&g_lifeMutex);
    if (g_finiing) { // destruction in progress, refuse re-init
        pthread_mutex_unlock(&g_lifeMutex);
        PwrLog(ERROR, "InitSockClient failed: client is being destroyed.");
        return PWR_ERR_COMMON;
    }
    if (g_sockInited) { // already initialized (connected OR reconnecting), idempotent
        pthread_mutex_unlock(&g_lifeMutex);
        return PWR_SUCCESS;
    }
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
    if (ret == PWR_SUCCESS) {
        g_sockInited = PWR_TRUE;
        pthread_mutex_unlock(&g_lifeMutex);
        return PWR_SUCCESS;
    }
    // Failed: undo what THIS attempt initialized, in place. Never route through
    // FiniSockClient(): ResetPwrMsgBuffer/ResetResultWaitingList are NOT safe to
    // run twice (they walk+free without re-zeroing msgList and destroy mutexes).
    FiniSockClientInternal();
    pthread_mutex_unlock(&g_lifeMutex);
    return ret;
}

static int FiniSockClientInternal(void)
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

int FiniSockClient(void)
{
    pthread_mutex_lock(&g_lifeMutex);
    if (g_finiing) { // re-entrant guard
        pthread_mutex_unlock(&g_lifeMutex);
        return PWR_SUCCESS;
    }
    if (!g_sockInited) { // already destroyed: nothing to drain or free. Running
        // the reset path twice would double-free buffer entries and lock
        // destroyed mutexes, so it must be a strict no-op here.
        pthread_mutex_unlock(&g_lifeMutex);
        return PWR_SUCCESS;
    }
    g_finiing = PWR_TRUE;
    pthread_mutex_unlock(&g_lifeMutex);

    // 1. Wake up every waiter so in-flight requests fail fast with an error code
    //    instead of hanging until timeout (and never touch freed nodes).
    BroadcastAllWaitingMsg(&g_waitList, PWR_ERR_DISCONNECTED);

    // 2. Wait for in-flight requests to leave. Requests that passed the status
    //    gate before g_finiing was set may add their node AFTER the first
    //    broadcast, so keep re-broadcasting each second. Bounded by
    //    FINI_DRAIN_TIME_OUT (> WAITING_RESULT_TIME_OUT) as a last resort.
    int waited = 0;
    pthread_mutex_lock(&g_lifeMutex);
    while (g_inflightReq > 0 && waited < FINI_DRAIN_TIME_OUT) {
        pthread_mutex_unlock(&g_lifeMutex);
        sleep(1);
        waited++;
        BroadcastAllWaitingMsg(&g_waitList, PWR_ERR_DISCONNECTED);
        pthread_mutex_lock(&g_lifeMutex);
    }
    if (g_inflightReq > 0) {
        PwrLog(ERROR, "FiniSockClient: %d request(s) still inflight after %ds, destroy anyway.",
               g_inflightReq, waited);
    }
    pthread_mutex_unlock(&g_lifeMutex);

    // 3. No business thread is using these resources anymore, safe to destroy.
    int ret = FiniSockClientInternal();

    pthread_mutex_lock(&g_lifeMutex);
    g_sockInited = PWR_FALSE;
    g_finiing = PWR_FALSE;
    pthread_mutex_unlock(&g_lifeMutex);
    return ret;
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
    if (IsFullBuffer(&g_sendBuff)) {
        PwrLog(ERROR, "Msg buffer is full. optType: %d", input.optType);
        return PWR_ERR_MSG_BUFFER_FULL;
    }

    // Lifecycle gate: reject requests while the client is being destroyed or
    // disconnected, and count this request as in-flight so FiniSockClient
    // waits for it before destroying shared resources.
    pthread_mutex_lock(&g_lifeMutex);
    if (g_finiing || g_sockFd == INVALID_FD) {
        pthread_mutex_unlock(&g_lifeMutex);
        PwrLog(ERROR, "Client not ready (destroying or disconnected). optType: %d", input.optType);
        return PWR_ERR_DISCONNECTED;
    }
    g_inflightReq++;
    pthread_mutex_unlock(&g_lifeMutex);

    int ret = PWR_SUCCESS;
    do {
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
            ret = PWR_ERR_SYS_EXCEPTION;
            break;
        }

        PwrMsg *rsp = NULL;
        ret = SendReqMsgAndWaitForRsp(req, &rsp);
        if (ret != PWR_SUCCESS) {
            PwrLog(ERROR, "Send req failed. optType: %d, ret: %d", input.optType, ret);
            ReleasePwrMsg(&req);
            ReleasePwrMsg(&rsp);
            break;
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
                ret = PWR_ERR_WRONG_RESPONSE_FROM_SERVER;
                break;
            }
        }

        PwrLog(DEBUG, "Request succeed. optType: %d", input.optType);
        ReleasePwrMsg(&req);
        ReleasePwrMsg(&rsp);
    } while (0);

    pthread_mutex_lock(&g_lifeMutex);
    g_inflightReq--;
    pthread_mutex_unlock(&g_lifeMutex);
    return ret;
}

PwrApiStatus GetPwrApiStatus()
{
    pthread_mutex_lock(&g_statusMutex);
    PwrApiStatus status = g_status;
    pthread_mutex_unlock(&g_statusMutex);
    return status;
}

int SetPwrApiStatus(PwrApiStatus status)
{
    pthread_mutex_lock(&g_statusMutex);
    g_status = status;
    pthread_mutex_unlock(&g_statusMutex);
    return PWR_SUCCESS;
}
