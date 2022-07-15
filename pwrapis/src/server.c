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
 * Description: provide server methods. socket and threads managerment, send/receive msg.
 * **************************************************************************** */
#include <server.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "common.h"
#include "log.h"
#include "pwrclient.h"
#include "config.h"
#include "pwrbuffer.h"
#include "cpuservice.h"

static int g_listenFd = -1;
static pthread_mutex_t g_listenFdLock = PTHREAD_MUTEX_INITIALIZER;
ThreadInfo g_sockProcThread;
ThreadInfo g_ServiceThread;

static PwrClient g_pwrClients[MAX_LICENT_NUM]; // 对该结构的读和写都在一个线程完成，因而不需要加锁
static PwrMsgBuffer g_sendBuff;                // 发送队列
static PwrMsgBuffer g_recvBuff;                // 接收队列
static pthread_mutex_t g_waitMsgMutex;
static pthread_cond_t g_waitMsgCond;

static int ListenStart(int sockFd, const struct sockaddr *addr)
{
    int ret;
    int reuse = 0x0;

    ret = setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int));
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "set reuse socket error %s errno: %d\n", strerror(errno), errno);
        return ERR_SYS_EXCEPTION;
    }
    ret = bind(sockFd, addr, sizeof(struct sockaddr));
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "bind socket error %s errno: %d\n", strerror(errno), errno);
        return ERR_SYS_EXCEPTION;
    }

    ret = listen(sockFd, MAX_PEDDING_SOCKS);
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "listen error %s errno: %d\n", strerror(errno), errno);
        return ERR_SYS_EXCEPTION;
    }
    g_listenFd = sockFd;

    return SUCCESS;
}

static int StartUnxListen(const char *localFileName)
{
    int sockFd = 0;
    struct sockaddr_un tSockaddr;

    // Delete the socket file
    unlink(localFileName);
    bzero(&tSockaddr, sizeof(tSockaddr));
    tSockaddr.sun_family = AF_UNIX;
    strcpy(tSockaddr.sun_path, localFileName);

    // Create a socket
    sockFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockFd < 0) {
        Logger(ERROR, MD_NM_SVR, "socket error %s errno: %d\n", strerror(errno), errno);
        return ERR_SYS_EXCEPTION;
    }
    return ListenStart(sockFd, (struct sockaddr *)&tSockaddr);
}

static void StopListen()
{
    pthread_mutex_lock(&g_listenFdLock);
    if (g_listenFd < 0) {
        return;
    } else {
        close(g_listenFd);
    }
    g_listenFd = INVALID_FD;
    pthread_mutex_unlock(&g_listenFdLock);
}

static void AcceptConnection()
{
    Logger(INFO, MD_NM_SVR, "Received connection request.");
    int newClientFd;
    struct sockaddr_un clientAddr;
    socklen_t socklen = sizeof(struct sockaddr_un);
    pthread_mutex_lock(&g_listenFdLock);
    newClientFd = accept(g_listenFd, (struct sockaddr *)&clientAddr, &socklen);
    pthread_mutex_unlock(&g_listenFdLock);
    if (newClientFd < 0) {
        Logger(ERROR, MD_NM_SVR, "accpet socket error: %s errno :%d, addr:%s", strerror(errno), errno,
            clientAddr.sun_path);
        return;
    }
    /*
    SetKeepAlive(newClientFd); todo 链路保活，后续完善 */
    PwrClient client;
    client.fd = newClientFd;
    unsigned char strSysId[MAX_SYSID_LEN] = {0};
    strncpy(strSysId, clientAddr.sun_path + strlen(CLIENT_ADDR), MAX_SYSID_LEN - 1);
    client.sysId = atoi(strSysId);
    if (AddToClientList(g_pwrClients, client) != SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Reach maximum connections or client existed : %d ", MAX_LICENT_NUM);
        close(newClientFd);
    }
    Logger(INFO, MD_NM_SVR, "Create new connection succeed. fd:%d, sysId:%d", client.fd, client.sysId);
}

static int ReadMsg(void *pData, int len, int dstFd, int idx)
{
    int leftLen;
    int recvLen;
    int readLen = 0;

    leftLen = len;
    bzero(pData, len);
    while (leftLen > 0) {
        recvLen = recv(dstFd, pData + readLen, leftLen, 0);
        if (recvLen < 0) {
            Logger(ERROR, MD_NM_SVR, "recv error %s errno:%d", strerror(errno), errno);
            DeleteFromClientList(g_pwrClients, idx);
            return ERR_SYS_EXCEPTION;
        } else if (recvLen == 0) {
            Logger(ERROR, MD_NM_SVR, "connection closed !");
            DeleteFromClientList(g_pwrClients, idx);
            return ERR_DISCONNECTED;
        }
        readLen += recvLen;
        leftLen -= recvLen;
    }
    return SUCCESS;
}

static void ProcessRecvMsgFromClient(int clientIdx)
{
    // 从connFd获取消息，并送到service队列，等待处理
    int dstFd = g_pwrClients[clientIdx].fd;
    PwrMsg *msg = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!msg || ReadMsg(msg, sizeof(PwrMsg), dstFd, clientIdx) != SUCCESS) {
        ReleasePwrMsg(&msg);
        return;
    }
    Logger(DEBUG, MD_NM_SVR, "receivd msg. opt:%d,sysId:%d", msg->head.optType, msg->head.sysId);

    if (msg->head.msgType != MT_REQ) {
        ReleasePwrMsg(&msg); // the server accept request msg only.
    }

    if (msg->head.dataLen > 0) {
        char *msgcontent = malloc(sizeof(msg->head.dataLen));
        if (!msgcontent || ReadMsg(msgcontent, sizeof(msg->head.dataLen), dstFd, clientIdx) != SUCCESS) {
            ReleasePwrMsg(&msg);
            return;
        }
        msg->data = msgcontent;
    } else {
        msg->data = NULL;
    }

    msg->head.sysId = g_pwrClients[clientIdx].sysId;
    if (AddToBufferTail(&g_recvBuff, msg) != SUCCESS) {
        ReleasePwrMsg(&msg);
    }
    // activate RunServiceProcess
    pthread_mutex_lock((pthread_mutex_t *)&g_waitMsgMutex);
    pthread_cond_signal((pthread_cond_t *)&g_waitMsgCond);
    pthread_mutex_unlock((pthread_mutex_t *)&g_waitMsgMutex);
}

static int WriteMsg(const void *pData, int len, int dstFd)
{
    int leftLen;
    int sendLen;
    int wrLen = 0;

    leftLen = len;
    while (leftLen > 0) {
        sendLen = send(dstFd, pData + wrLen, leftLen, 0);
        if (sendLen < 0) {
            Logger(ERROR, MD_NM_SVR, "send error %s errno:%d", strerror(errno), errno);
            DeleteFromClientList(g_pwrClients, GetIdxByFd(g_pwrClients, dstFd));
            return ERR_SYS_EXCEPTION;
        }
        leftLen -= sendLen;
        wrLen += sendLen;
    }
    return SUCCESS;
}

static void ProcessSendMsgToClient()
{
    // 从缓存中读取待发送消息，并发送出去
    int count = 0;
    static char data[MAX_DATA_SIZE];
    while (!IsEmptyBuffer(&g_sendBuff) && count < 5) {
        PwrMsg *msg = PopFromBufferHead(&g_sendBuff);
        count++;
        if (!msg) {
            continue;
        }

        int dstFd = GetFdBySysId(g_pwrClients, msg->head.sysId);
        if (dstFd == INVALID_FD) {
            ReleasePwrMsg(&msg);
            continue;
        }
        int len = sizeof(PwrMsg) + msg->head.dataLen;

        if (len <= MAX_DATA_SIZE) {
            memcpy(data, msg, sizeof(PwrMsg));
            memcpy(data + sizeof(PwrMsg), msg->data, msg->head.dataLen);
            WriteMsg(data, len, dstFd);
        } else {
            memcpy(data, msg, sizeof(PwrMsg));
            memcpy(data + sizeof(PwrMsg), msg->data, MAX_DATA_SIZE - sizeof(PwrMsg));
            WriteMsg(data, MAX_DATA_SIZE, dstFd);
            int datasent = MAX_DATA_SIZE - sizeof(PwrMsg);
            int leftLen = len - MAX_DATA_SIZE;
            while (leftLen > MAX_DATA_SIZE) {
                memcpy(data, msg->data + datasent, MAX_DATA_SIZE);
                WriteMsg(data, MAX_DATA_SIZE, dstFd);
                datasent += MAX_DATA_SIZE;
                leftLen -= MAX_DATA_SIZE;
            }
            memcpy(data, msg->data + datasent, leftLen);
            WriteMsg(data, leftLen, dstFd);
        }
        Logger(DEBUG, MD_NM_SVR, "send msg. opt:%d,sysId:%d", msg->head.optType, msg->head.sysId);
        ReleasePwrMsg(&msg);
    }
}

/**
 * RunServerSocketProcess - Run RunServerSocketProcess
 * 1. Accepting connection request
 * 2. Receiving msg from or send msg to client FDs
 */
static void *RunServerSocketProcess()
{
    fd_set recvFdSet;
    int maxFd = INVALID_FD;
    struct timeval tv;
    InitPwrClient(g_pwrClients);
    while (g_sockProcThread.keepRunning) {
        tv.tv_sec = 0;
        tv.tv_usec = THREAD_LOOP_INTERVAL;
        FD_ZERO(&recvFdSet);
        maxFd = g_listenFd;
        FD_SET(g_listenFd, &recvFdSet);

        for (int i = 0; i < MAX_LICENT_NUM; i++) {
            if (g_pwrClients[i].fd != INVALID_FD) {
                FD_SET(g_pwrClients[i].fd, &recvFdSet);
                maxFd = maxFd < g_pwrClients[i].fd ? g_pwrClients[i].fd : maxFd;
            }
        }

        if (!IsEmptyBuffer(&g_sendBuff)) {
            ProcessSendMsgToClient();
        }
        // todo: select中增加断连异常事件监听
        int ret = select(maxFd + 1, &recvFdSet, NULL, NULL, &tv);
        if (ret <= 0) {
            continue;
        }

        if (FD_ISSET(g_listenFd, &recvFdSet)) { // new connection
            AcceptConnection();
        }

        for (int i = 0; i < MAX_LICENT_NUM; i++) {
            if (FD_ISSET(g_pwrClients[i].fd, &recvFdSet)) { // new msg in
                ProcessRecvMsgFromClient(i);
            }
        }
    } // while

    CloseAllConnections(g_pwrClients);
}

static void WaitForMsg()
{
    struct timeval now;
    struct timespec outTime;
    pthread_mutex_lock((pthread_mutex_t *)&g_waitMsgMutex);
    gettimeofday(&now, NULL);
    outTime.tv_sec = now.tv_sec;
    outTime.tv_nsec = (now.tv_usec + THREAD_LOOP_INTERVAL) * 1000;
    pthread_cond_timedwait((pthread_cond_t *)&g_waitMsgCond, (pthread_mutex_t *)&g_waitMsgMutex, &outTime);
    pthread_mutex_unlock((pthread_mutex_t *)&g_waitMsgMutex);
}

static void ProcessReqMsg(PwrMsg *req)
{
    switch (req->head.optType) {
        case GET_CPU_USAGE:
            GetCpuUsage(req);
            break;
        case GET_CPU_CACHE_MISS:
            // todo
            break;
        case GET_CPU_TOP:
            // todo
            break;
        case GET_DISK_IO_RATE:
            // todo
            break;
        default:
            break;
    }
    ReleasePwrMsg(&req);
}


/**
 * RunServiceProcess - Run RunServiceProcess
 * Process the request msg in receiving buffer g_recvBuff
 */
static void *RunServiceProcess()
{
    while (g_ServiceThread.keepRunning) {
        if (IsEmptyBuffer(&g_recvBuff)) {
            WaitForMsg();
        }
        PwrMsg *msg = PopFromBufferHead(&g_recvBuff);
        if (!msg) {
            continue;
        }
        ProcessReqMsg(msg);
    } // while
}
// public======================================================================================
// Init Socket. Start listening & accepting
int StartServer()
{
    InitMsgFactory();
    InitPwrMsgBuffer(&g_sendBuff);
    InitPwrMsgBuffer(&g_recvBuff);
    InitThreadInfo(&g_ServiceThread);
    InitThreadInfo(&g_sockProcThread);
    pthread_mutex_init((pthread_mutex_t *)&g_waitMsgMutex, NULL);
    pthread_cond_init((pthread_cond_t *)&g_waitMsgCond, NULL);
    int ret;
    ret = StartUnxListen(GetServCfg()->sockFile);
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "%s Listen failed! ret[%d]", GetServCfg(), ret);
        return ERR_SYS_EXCEPTION;
    }

    ret = CreateThread(&g_ServiceThread, RunServiceProcess);
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Create service thread failed! ret[%d]", ret);
        return ERR_SYS_EXCEPTION;
    }

    ret = CreateThread(&g_sockProcThread, RunServerSocketProcess);
    if (ret != SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Create ServerSocketProcess thread failed! ret[%d]", ret);
        return ERR_SYS_EXCEPTION;
    }
    return SUCCESS;
}

void StopServer()
{
    FiniThreadInfo(&g_sockProcThread);
    FiniThreadInfo(&g_ServiceThread);
    StopListen();
    ResetPwrMsgBuffer(&g_sendBuff);
    ResetPwrMsgBuffer(&g_recvBuff);
    pthread_cond_destroy((pthread_cond_t *)&g_waitMsgCond);
    pthread_mutex_destroy((pthread_mutex_t *)&g_waitMsgMutex);
}

int SendRspMsg(PwrMsg *rsp)
{
    return AddToBufferTail(&g_sendBuff, rsp);
}