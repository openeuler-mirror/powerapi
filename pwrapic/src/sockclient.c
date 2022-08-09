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
#include <errno.h>
#include "pwrlog.h"
#include "pwrerr.h"
#include "pwrbuffer.h"

#define CLIENT_ADDR "pwrclient.sock."
#define SERVER_ADDR "pwrserver.sock"
#define INVALID_FD (-1)
#define SOCK_THREAD_LOOP_INTERVAL 2000 // us
#define RECONNECTE_INTERVAL 3          // s
#define MAX_PID_LEN 12
#define MAX_PROC_NUM_IN_ONE_LOOP 5

static int g_sockFd = INVALID_FD;
static ThreadInfo g_sockThread;

static PwrMsgBuffer g_sendBuff;         // 发送队列
static PwrMsgBuffer g_recvBuff;         // 接收队列
static ResultWaitingMsgList g_waitList; // 等待结果列表

#define CHECK_SOCKET_STATUS()                         \
    if (g_sockFd == INVALID_FD) {                     \
        PwrLog(ERROR, "check socket status failed."); \
        return ERR_DISCONNECTED;                      \
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
            PwrLog(ERROR, "recv error %s errno:%d", strerror(errno), errno);
            close(g_sockFd);
            g_sockFd = INVALID_FD;
            return ERR_SYS_EXCEPTION;
        } else if (recvLen == 0) {
            PwrLog(ERROR, "connection closed !");
            g_sockFd = INVALID_FD;
            return ERR_DISCONNECTED;
        }
        readLen += recvLen;
        leftLen -= recvLen;
    }
    return SUCCESS;
}

static int WriteMsg(const void *pData, int len)
{
    int leftLen;
    int sendLen;
    int wrLen = 0;

    leftLen = len;
    while (leftLen > 0) {
        sendLen = send(g_sockFd, pData + wrLen, leftLen, 0);
        if (sendLen < 0) {
            PwrLog(ERROR, "send error %s errno:%d", strerror(errno), errno);
            close(g_sockFd);
            g_sockFd = INVALID_FD;
            return ERR_SYS_EXCEPTION;
        }
        leftLen -= sendLen;
        wrLen += sendLen;
    }
    return SUCCESS;
}

static void ProcessRspMsg(PwrMsg *rsp)
{
    ResultWaitingMsgNode *rwm = FindAndMoveWaitingMsg(&g_waitList, rsp->head.seqId);
    if (!rwm) {
        ReleasePwrMsg(&rsp);
        return; // drop this msg
    }
    rwm->rspMsg = rsp;
    if (DoRspToWaitingMsg(rwm) != SUCCESS) {
        ReleasePwrMsg(&rsp);
        return;
    }
}

static void ProcessOtherMsg(PwrMsg *msg)
{
    if (AddToBufferTail(&g_recvBuff, msg) != SUCCESS) {
        ReleasePwrMsg(&msg);
    }
}

static void RecvMsgFromSocket(void)
{
    PwrMsg *msg = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!msg || ReadMsg(msg, sizeof(PwrMsg)) != SUCCESS) {
        ReleasePwrMsg(&msg);
        return;
    }

    if (msg->head.dataLen != 0) {
        char *msgcontent = malloc(msg->head.dataLen);
        if (!msgcontent || ReadMsg(msgcontent, msg->head.dataLen) != SUCCESS) {
            ReleasePwrMsg(&msg);
            return;
        }
        msg->data = msgcontent;
    } else {
        msg->data=NULL;
    }

    if (msg->head.msgType == MT_RSP) {
        ProcessRspMsg(msg);
    } else {
        ProcessOtherMsg(msg);
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
        int len = sizeof(PwrMsg) + msg->head.dataLen;

        if (len <= MAX_DATA_SIZE) {
            memcpy(data, msg, sizeof(PwrMsg));
            memcpy(data + sizeof(PwrMsg), msg->data, msg->head.dataLen);
            WriteMsg(data, len);
        } else {
            memcpy(data, msg, sizeof(PwrMsg));
            memcpy(data + sizeof(PwrMsg), msg->data, MAX_DATA_SIZE - sizeof(PwrMsg));
            WriteMsg(data, MAX_DATA_SIZE);
            int datasent = MAX_DATA_SIZE - sizeof(PwrMsg);
            int leftLen = len - MAX_DATA_SIZE;
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
        PwrLog(ERROR, "create socket failed. ret:%d", clientFd);
        return ERR_COMMON;
    }
    // bind
    struct sockaddr_un clientAddr;
    bzero(&clientAddr, sizeof(clientAddr));
    clientAddr.sun_family = AF_UNIX;
    char pidStr[MAX_PID_LEN];
    pid_t pid = getpid();
    if (sprintf(pidStr, "%d", pid) < 0) {
        close(clientFd);
        return ERR_SYS_EXCEPTION;
    }
    strncpy(clientAddr.sun_path, CLIENT_ADDR, sizeof(clientAddr.sun_path) - 1);
    // socket file "pwrclient.sock.{$pid}"
    strncat(clientAddr.sun_path, pidStr, sizeof(clientAddr.sun_path) - strlen(CLIENT_ADDR) - 1);
    int clen = SUN_LEN(&clientAddr);
    unlink(clientAddr.sun_path);
    if (bind(clientFd, (struct sockaddr *)&clientAddr, clen) < 0) {
        PwrLog(ERROR, "bind socket failed.");
        close(clientFd);
        return ERR_COMMON;
    }
    // connect
    struct sockaddr_un serverAddr;
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sun_family = AF_UNIX;
    strncpy(serverAddr.sun_path, SERVER_ADDR, sizeof(serverAddr.sun_path) - 1);
    int slen = SUN_LEN(&serverAddr);
    if (connect(clientFd, (struct sockaddr *)&serverAddr, slen) < 0) {
        PwrLog(ERROR, "connect to server failed.");
        close(clientFd);
        return ERR_COMMON;
    }

    g_sockFd = clientFd;
    PwrLog(INFO, "connect to server succeed. fd:%d", g_sockFd);
    return SUCCESS;
}

static void *RunSocketProcess(void *none)
{
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

        // todo: select中增加断连异常事件监听
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
        return ERR_NULL_POINTER;
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
        return ERR_SYS_EXCEPTION;
    }
    node->reqMsg = msg;
    AddToWaitingListTail(&g_waitList, node);
    int ret = WaitingForResponse(node);
    if (ret != SUCCESS) {
        // timeout or error scenario. the msg still waiting in the list. need to move out.
        MoveOutWaitingMsg(&g_waitList, node);
    }
    *rsp = node->rspMsg;
    node->reqMsg = NULL;
    node->rspMsg = NULL;
    ReleaseResultWaitingMsgNode(node);
    return SUCCESS;
}

static int SendReqMsgAndWaitForRsp(PwrMsg *req, PwrMsg **rsp)
{
    if (!req || !rsp) {
        return ERR_NULL_POINTER;
    }
    CHECK_SOCKET_STATUS();

    if (SendMsgSyn(req, rsp) != SUCCESS) {
        PwrLog(ERROR, "send msg to server failed. optType: %d, seqId:%u", req->head.optType, req->head.seqId);
        return ERR_SYS_EXCEPTION;
    }

    if (*rsp == NULL || (*rsp)->head.rspCode != SUCCESS) {
        PwrLog(ERROR, "rsp error. optType: %d, seqId:%u", req->head.optType, req->head.seqId);
        return *rsp == NULL ? ERR_COMMON : (*rsp)->head.rspCode;
    }
    return SUCCESS;
}

// public****************************************************************************************/
int InitSockClient(void)
{
    InitPwrMsgBuffer(&g_sendBuff);
    InitPwrMsgBuffer(&g_recvBuff);
    InitResultWaitingList(&g_waitList);
    InitMsgFactory();
    InitThreadInfo(&g_sockThread);
    int ret = SUCCESS;
    do {
        if (CreateConnection() != SUCCESS) {
            ret = ERR_COMMON;
            break;
        }
        int r = CreateThread(&g_sockThread, RunSocketProcess);
        if (r != SUCCESS) {
            PwrLog(ERROR, "Create recv thread failed. ret[%d]", r);
            ret = ERR_COMMON;
            break;
        }
    } while (0);
    if (ret != SUCCESS) {
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
    return SUCCESS;
}

int SendReqAndWaitForRsp(ReqInputParam input, RspOutputParam output)
{
    if ((output.rspData && (!output.rspBuffSize || *output.rspBuffSize == 0))) {
        return ERR_INVALIDE_PARAM;
    }

    char *inputData = NULL;
    if (input.data && input.dataLen != 0) {
        inputData = (char *)malloc(input.dataLen);
        bzero(inputData, input.dataLen);
        memcpy(inputData, input.data, input.dataLen);
    }

    PwrMsg *req = CreateReqMsg(input.optType, input.taskNo, input.dataLen, inputData);
    if (!req) {
        PwrLog(ERROR, "Create req msg failed. optType:%d", input.optType);
        free(inputData);
        return ERR_SYS_EXCEPTION;
    }

    PwrMsg *rsp = NULL;
    int ret = SendReqMsgAndWaitForRsp(req, &rsp);
    if (ret != SUCCESS) {
        PwrLog(ERROR, "Send req failed. optType:%d, ret:%d", input.optType, ret);
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
            return ERR_WRONG_RESPONSE_FROM_SERVER;
        }
    }

    PwrLog(DEBUG, "Request Succeed. optType:%d", input.optType);
    ReleasePwrMsg(&req);
    ReleasePwrMsg(&rsp);
    return SUCCESS;
}
