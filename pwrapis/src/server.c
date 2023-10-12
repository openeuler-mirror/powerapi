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
 * Author: queyanwen,wuhaotian
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
#include "sysservice.h"
#include "cpuservice.h"
#include "taskservice.h"
#include "comservice.h"
#include "diskservice.h"
#include "pwrerr.h"
#include "utils.h"
#define COUNT_MAX 5

static int g_listenFd = -1;
static pthread_mutex_t g_listenFdLock = PTHREAD_MUTEX_INITIALIZER;
static ThreadInfo g_sockProcThread;
static ThreadInfo g_serviceThread;

static PwrClient g_pwrClients[MAX_CLIENT_NUM]; // Reading and writing the struct are done in one thread, no need locks
static PwrMsgBuffer g_sendBuff;                // Send queue
static PwrMsgBuffer g_recvBuff;                // Receive queue
static pthread_mutex_t g_waitMsgMutex;
static pthread_cond_t g_waitMsgCond;

static int ListenStart(int sockFd, const struct sockaddr_un *addr)
{
    int ret;
    int reuse = 0x0;

    ret = setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int));
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "set reuse socket error %s errno: %d\n", strerror(errno), errno);
        return PWR_ERR_SYS_EXCEPTION;
    }
    ret = bind(sockFd, (struct sockaddr *)addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "bind socket error %s errno: %d\n", strerror(errno), errno);
        return PWR_ERR_SYS_EXCEPTION;
    }

    /* Set the permissions of the pwrserver.sock to 722 */
    mode_t mode = 0722;
    ret = chmod(addr->sun_path, mode);
    if (ret == -1) {
        Logger(ERROR, MD_NM_SVR, "set permission error");
        return PWR_ERR_SYS_EXCEPTION;
    }

    ret = listen(sockFd, MAX_PEDDING_SOCKS);
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "listen error %s errno: %d\n", strerror(errno), errno);
        return PWR_ERR_SYS_EXCEPTION;
    }
    g_listenFd = sockFd;

    return PWR_SUCCESS;
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
        return PWR_ERR_SYS_EXCEPTION;
    }
    return ListenStart(sockFd, (struct sockaddr_un *)&tSockaddr);
}

static void StopListen(void)
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

static int PassCredVerification(const int sockfd, pid_t *pid)
{
    int ret;
    struct ucred credSocket;
    UnixCredOS credOS;
    socklen_t socklen = sizeof(struct ucred);
    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &credSocket, &socklen) < 0) {
        Logger(ERROR, MD_NM_SVR, "get sock opt failed");
        return PWR_ERR_COMMON;
    }

    ret = GetSockoptFromOS(*pid, &credOS);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "get sockopt from OS failed, ret : %d", ret);
        return PWR_ERR_COMMON;
    }

    if (credSocket.uid != credOS.uid || credSocket.gid != credOS.gid) {
        Logger(ERROR, MD_NM_SVR, "uid or gid from socket and OS are different");
        return PWR_ERR_COMMON;
    }

    if (!IsAdmin(credOS.user) && !IsObserver(credOS.user)) {
        Logger(ERROR, MD_NM_SVR, "the client <%s> is not in white list", credOS.user);
        return PWR_ERR_COMMON;
    }

    *pid = credOS.pid;
    return PWR_SUCCESS;
}

static PWR_COM_EventInfo* CreateEventInfo(const char *info, PWR_COM_EVT_TYPE eventType)
{
    size_t eventInfoLen = sizeof(PWR_COM_EventInfo) + strlen(info);
    PWR_COM_EventInfo *eventInfo = (PWR_COM_EventInfo *)malloc(eventInfoLen);
    if (!eventInfo) {
        return NULL;
    }

    bzero(eventInfo, sizeof(PWR_COM_EventInfo));
    GetCurFullTime(eventInfo->ctime, PWR_MAX_TIME_LEN);
    eventInfo->eventType = eventType;
    eventInfo->infoLen = strlen(info);
    strcpy(eventInfo->info, info);
    return eventInfo;
}

static int SendEventToClient(const int dstFd, const uint32_t sysId, char *data, uint32_t len);
static void AcceptConnection(void)
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

    if (PassCredVerification(newClientFd, &client.sysId) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_CRED, "credentials verification failed");
        const char *info = "Server has closed connection. This client is not in white list";
        /* eventData should be release in the function that uses it */
        PWR_COM_EventInfo *eventInfo = CreateEventInfo(info, PWR_COM_EVTTYPE_CRED_FAILED);
        if (!eventInfo) {
            Logger(ERROR, MD_NM_SVR, "Create event failed.");
            close(newClientFd);
            return;
        }

        SendEventToClient(newClientFd, client.sysId, (char *)eventInfo,
            sizeof(PWR_COM_EventInfo) + strlen(info));
        close(newClientFd);
        return;
    }

    if (AddToClientList(g_pwrClients, client) != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Reach maximum connections or client existed : %d ", MAX_CLIENT_NUM);
        close(newClientFd);
        return;
    }
    Logger(INFO, MD_NM_SVR, "Create new connection succeed. fd:%d, sysId:%d", client.fd, client.sysId);
}

static void CleanClientResource(PwrClient *pwrClient, int idx)
{
    CleanControlAuth(pwrClient->sysId);
    CleanDataCollTaskByClient(pwrClient->sysId);
    DeleteFromClientList(g_pwrClients, idx);
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
            if (recvLen == EINTR || recvLen == EWOULDBLOCK || recvLen == EAGAIN) {
                continue;
            }
            Logger(ERROR, MD_NM_SVR, "recv error %s errno:%d", strerror(errno), errno);
            CleanClientResource(g_pwrClients, idx);
            return PWR_ERR_SYS_EXCEPTION;
        } else if (recvLen == 0) {
            Logger(ERROR, MD_NM_SVR, "connection closed !");
            CleanClientResource(g_pwrClients, idx);
            return PWR_ERR_DISCONNECTED;
        }
        readLen += recvLen;
        leftLen -= recvLen;
    }
    return PWR_SUCCESS;
}

static void ProcessRecvMsgFromClient(int clientIdx)
{
    // Get msg from connFd, send to service queue and waiting for processing
    int dstFd = g_pwrClients[clientIdx].fd;
    PwrMsg *msg = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!msg || ReadMsg(msg, sizeof(PwrMsg), dstFd, clientIdx) != PWR_SUCCESS) {
        ReleasePwrMsg(&msg);
        return;
    }
    Logger(DEBUG, MD_NM_SVR, "receivd msg. opt:%d,sysId:%d", msg->head.optType, msg->head.sysId);

    if (msg->head.msgType != MT_REQ) {
        ReleasePwrMsg(&msg); // the server accept request msg only.
    }

    if (msg->head.dataLen > 0) {
        char *msgcontent = malloc(msg->head.dataLen);
        if (!msgcontent || ReadMsg(msgcontent, msg->head.dataLen, dstFd, clientIdx) != PWR_SUCCESS) {
            ReleasePwrMsg(&msg);
            return;
        }
        msg->data = msgcontent;
    } else {
        msg->data = NULL;
    }

    if (msg->head.sysId != g_pwrClients[clientIdx].sysId) {
        ReleasePwrMsg(&msg);
        return;
    }

    if (AddToBufferTail(&g_recvBuff, msg) != PWR_SUCCESS) {
        ReleasePwrMsg(&msg);
    }
    // activate RunServiceProcess
    pthread_mutex_lock((pthread_mutex_t *)&g_waitMsgMutex);
    pthread_cond_signal((pthread_cond_t *)&g_waitMsgCond);
    pthread_mutex_unlock((pthread_mutex_t *)&g_waitMsgMutex);
}

static int WriteMsg(const void *pData, size_t len, int dstFd)
{
    size_t leftLen;
    size_t sendLen;
    size_t wrLen = 0;

    leftLen = len;
    while (leftLen > 0) {
        sendLen = send(dstFd, pData + wrLen, leftLen, 0);
        if (sendLen < 0) {
            if (sendLen == EINTR || sendLen == EWOULDBLOCK || sendLen == EAGAIN) {
                continue;
            }
            Logger(ERROR, MD_NM_SVR, "send error %s errno:%d", strerror(errno), errno);
            CleanClientResource(g_pwrClients, GetIdxByFd(g_pwrClients, dstFd));
            return PWR_ERR_SYS_EXCEPTION;
        } else if (sendLen == 0) {
            Logger(ERROR, MD_NM_SVR, "connection closed !");
            CleanClientResource(g_pwrClients, GetIdxByFd(g_pwrClients, dstFd));
            return PWR_ERR_DISCONNECTED;
        }
        leftLen -= sendLen;
        wrLen += sendLen;
    }
    return PWR_SUCCESS;
}

static void SendMsgToClientAction(int dstFd, PwrMsg *msg)
{
    static char data[MAX_DATA_SIZE];
    size_t len = sizeof(PwrMsg) + msg->head.dataLen;

    if (len <= MAX_DATA_SIZE) {
        memcpy(data, msg, sizeof(PwrMsg));
        memcpy(data + sizeof(PwrMsg), msg->data, msg->head.dataLen);
        WriteMsg(data, len, dstFd);
    } else {
        memcpy(data, msg, sizeof(PwrMsg));
        memcpy(data + sizeof(PwrMsg), msg->data, MAX_DATA_SIZE - sizeof(PwrMsg));
        WriteMsg(data, MAX_DATA_SIZE, dstFd);
        size_t datasent = MAX_DATA_SIZE - sizeof(PwrMsg);
        size_t leftLen = len - MAX_DATA_SIZE;
        while (leftLen > MAX_DATA_SIZE) {
            memcpy(data, msg->data + datasent, MAX_DATA_SIZE);
            WriteMsg(data, MAX_DATA_SIZE, dstFd);
            datasent += MAX_DATA_SIZE;
            leftLen -= MAX_DATA_SIZE;
        }
        memcpy(data, msg->data + datasent, leftLen);
        WriteMsg(data, leftLen, dstFd);
    }
}

static int SendEventToClient(const int dstFd, const uint32_t sysId, char *data, uint32_t len)
{
    if (!data && len != 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    PwrMsg *event = (PwrMsg *)malloc(sizeof(PwrMsg));
    char *dataCpy = (char *)malloc(len);
    if (!event || !dataCpy) {
        Logger(ERROR, MD_NM_SVR, "Malloc failed");
        free(data);
        return PWR_ERR_SYS_EXCEPTION;
    }

    bzero(event, sizeof(PwrMsg));
    memset(dataCpy, 0, len);
    memcpy(dataCpy, data, len);
    int res = GenerateEventMsg(event, sysId, dataCpy, len);
    if (res != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Generate event msg failed, result:%d", res);
        free(data);
        data = NULL;
        ReleasePwrMsg(&event);
        return res;
    }

    SendMsgToClientAction(dstFd, event);
    Logger(INFO, MD_NM_SVR, "Send event notifcation success.");
    free(data);
    data = NULL;
    ReleasePwrMsg(&event);
    return PWR_SUCCESS;
}

static void ProcessSendMsgToClient(void)
{
    // Read msg from buffer and send.
    int count = 0;
    while (!IsEmptyBuffer(&g_sendBuff) && count < COUNT_MAX) {
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
        SendMsgToClientAction(dstFd, msg);
        Logger(DEBUG, MD_NM_SVR, "send msg. opt:%d,sysId:%d", msg->head.optType, msg->head.sysId);
        ReleasePwrMsg(&msg);
    }
}

/**
 * RunServerSocketProcess - Run RunServerSocketProcess
 * 1. Accepting connection request
 * 2. Receiving msg from or send msg to client FDs
 */
static void *RunServerSocketProcess(void *none)
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

        for (int i = 0; i < MAX_CLIENT_NUM; i++) {
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

        for (int i = 0; i < MAX_CLIENT_NUM; i++) {
            if (FD_ISSET(g_pwrClients[i].fd, &recvFdSet)) { // new msg in
                ProcessRecvMsgFromClient(i);
            }
        }
    } // while

    CloseAllConnections(g_pwrClients);
}

static void WaitForMsg(void)
{
    struct timeval now;
    struct timespec outTime;
    pthread_mutex_lock((pthread_mutex_t *)&g_waitMsgMutex);
    gettimeofday(&now, NULL);
    outTime.tv_sec = now.tv_sec;
    outTime.tv_nsec = (now.tv_usec + THREAD_LOOP_INTERVAL) * THOUSAND;
    pthread_cond_timedwait((pthread_cond_t *)&g_waitMsgCond, (pthread_mutex_t *)&g_waitMsgMutex, &outTime);
    pthread_mutex_unlock((pthread_mutex_t *)&g_waitMsgMutex);
}

static OptToFunct g_optToFunct[] = {
    {COM_CREATE_DC_TASK, CreateDataCollTask},
    {COM_DELETE_DC_TASK, DeleteDataCollTask},
    {COM_REQUEST_CONTROL_AUTH, RequestControlAuth},
    {COM_RELEASE_CONTROL_AUTH, ReleaseControlAuth},
    {SYS_SET_POWER_STATE, SetSysPowerState},
    {SYS_GET_RT_POWER, GetSysRtPowerInfo},
    {CPU_GET_USAGE, GetCpuUsage},
    {CPU_GET_PERF_DATA, GetCpuPerfData},
    {CPU_GET_INFO, GetCpuinfo},
    {CPU_GET_FREQ_GOVERNOR, GetCpuFreqGovernor},
    {CPU_SET_FREQ_GOVERNOR, SetCpuFreqGovernor},
    {CPU_GET_FREQ_GOV_ATTRS, GetCpuFreqGovAttrs},
    {CPU_GET_FREQ_GOV_ATTR, GetCpuFreqGovAttr},
    {CPU_SET_FREQ_GOV_ATTR, SetCpuFreqGovAttr},
    {CPU_GET_CUR_FREQ, GetCpuFreq},
    {CPU_SET_CUR_FREQ, SetCpuFreq},
    {CPU_GET_FREQ_ABILITY, GetCpuFreqAbility},
    {CPU_GET_FREQ_RANGE, GetCpuFreqRange},
    {CPU_SET_FREQ_RANGE, SetCpuFreqRange}
};

static void ProcessReqMsg(PwrMsg *req)
{
    Logger(DEBUG, MD_NM_SVR, "Get Req msg. seqId:%u, sysId:%d, optType:%d",
        req->head.seqId, req->head.sysId, req->head.optType);
    int count = sizeof(g_optToFunct) / sizeof(g_optToFunct[0]);
    for (int i = 0; i < count; i++) {
        if (req->head.optType == g_optToFunct[i].type) {
            g_optToFunct[i].funct(req);
            break;
        }
    }
    ReleasePwrMsg(&req);
}

/**
 * RunServiceProcess - Run RunServiceProcess
 * Process the request msg in receiving buffer g_recvBuff
 */
static void *RunServiceProcess(void *none)
{
    while (g_serviceThread.keepRunning) {
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

static inline int SendMsg(PwrMsg *msg)
{
    return AddToBufferTail(&g_sendBuff, msg);
}

// public======================================================================================
// Init Socket. Start listening & accepting
int StartServer(void)
{
    InitMsgFactory();
    InitPwrMsgBuffer(&g_sendBuff);
    InitPwrMsgBuffer(&g_recvBuff);
    InitThreadInfo(&g_serviceThread);
    InitThreadInfo(&g_sockProcThread);
    pthread_mutex_init((pthread_mutex_t *)&g_waitMsgMutex, NULL);
    pthread_cond_init((pthread_cond_t *)&g_waitMsgCond, NULL);
    int ret;
    ret = StartUnxListen(GetServCfg()->sockFile);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "%s Listen failed! ret[%d]", GetServCfg(), ret);
        return PWR_ERR_SYS_EXCEPTION;
    }

    ret = CreateThread(&g_serviceThread, RunServiceProcess, NULL);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Create service thread failed! ret[%d]", ret);
        return PWR_ERR_SYS_EXCEPTION;
    }

    ret = CreateThread(&g_sockProcThread, RunServerSocketProcess, NULL);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Create ServerSocketProcess thread failed! ret[%d]", ret);
        return PWR_ERR_SYS_EXCEPTION;
    }
    InitTaskService();
    return PWR_SUCCESS;
}

void StopServer(void)
{
    FiniTaskService();
    FiniThreadInfo(&g_sockProcThread);
    FiniThreadInfo(&g_serviceThread);
    StopListen();
    ResetPwrMsgBuffer(&g_sendBuff);
    ResetPwrMsgBuffer(&g_recvBuff);
    DestroyMsgFactory();
    pthread_cond_destroy((pthread_cond_t *)&g_waitMsgCond);
    pthread_mutex_destroy((pthread_mutex_t *)&g_waitMsgMutex);
    ReleaseWhiteList();
}

// This function will move the 'data' pointer to data migration, and the caller should not release the 'data'.
void SendRspToClient(const PwrMsg *req, int rspCode, char *data, uint32_t len)
{
    if (!req) {
        return;
    }
    if (!data && len != 0) {
        return;
    }

    PwrMsg *rsp = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!rsp) {
        Logger(ERROR, MD_NM_SVR, "Malloc failed.");
        free(data);
        return;
    }
    bzero(rsp, sizeof(PwrMsg));
    GenerateRspMsg(req, rsp, rspCode, data, len);
    if (SendRspMsg(rsp) != PWR_SUCCESS) {
        ReleasePwrMsg(&rsp);
    }
}
// This function will move the 'data' pointer to data migration, and the caller should not release the 'data'.
int SendMetadataToClient(uint32_t sysId, char *data, uint32_t len)
{
    if (!data && len != 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }
    PwrMsg *metadata = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!metadata) {
        Logger(ERROR, MD_NM_SVR, "Malloc failed.");
        free(data);
        return PWR_ERR_SYS_EXCEPTION;
    }
    bzero(metadata, sizeof(PwrMsg));
    GenerateMetadataMsg(metadata, sysId, data, len);
    if (SendMsg(metadata)) {
        ReleasePwrMsg(&metadata);
    }
}

int SendRspMsg(PwrMsg *rsp)
{
    return AddToBufferTail(&g_sendBuff, rsp);
}
