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
#include "procservice.h"
#include "pwrerr.h"
#include "utils.h"
#include "hbmservice.h"

#define THREAD_LOOP_INTERVAL 2000 // us

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
        Logger(ERROR, MD_NM_SVR, "set reuse socket error %s errno: %d", strerror(errno), errno);
        return PWR_ERR_SYS_EXCEPTION;
    }
    ret = bind(sockFd, (struct sockaddr *)addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        Logger(ERROR, MD_NM_SVR, "bind socket error %s errno: %d", strerror(errno), errno);
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
        Logger(ERROR, MD_NM_SVR, "listen error %s errno: %d", strerror(errno), errno);
        return PWR_ERR_SYS_EXCEPTION;
    }
    g_listenFd = sockFd;

    return PWR_SUCCESS;
}

#define SOCK_DIR_PERM 0755
static int CheckAndCreateSockPath(const char *filepath)
{
    char path[MAX_FULL_NAME] = {0};
    if (GetPath(filepath, path) != PWR_SUCCESS || IsPathOk(path) == WRONG_PATH) {
            fprintf(stderr, "Wrong sock file path: %s\n", filepath);
            return PWR_ERR_SYS_EXCEPTION;
    }

    if (access(path, F_OK) != 0) {
        if (MkDirs(path, SOCK_DIR_PERM) != PWR_SUCCESS) {
            perror("access sock file path failed.\n");
            return PWR_ERR_SYS_EXCEPTION;
        }
    }
    return PWR_SUCCESS;
}

static int StartUnxListen(const char *localFileName)
{
    int ret = CheckAndCreateSockPath(localFileName);
    if (ret != PWR_SUCCESS) {
        return ret;
    }

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
        Logger(ERROR, MD_NM_SVR, "socket error %s errno: %d", strerror(errno), errno);
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

static int PassCredVerification(const struct ucred *credSocket, char *userName)
{
    int ret;
    UnixCredOS credOS = {0};

    ret = GetSockoptFromOS(credSocket->pid, &credOS);
    if (ret != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "get sockopt from OS failed, ret : %d", ret);
        return PWR_ERR_COMMON;
    }

    if (credSocket->uid != credOS.uid || credSocket->gid != credOS.gid) {
        Logger(ERROR, MD_NM_SVR, "uid or gid from socket and OS are different");
        return PWR_ERR_COMMON;
    }

    if (!IsAdmin(credOS.user) && !IsObserver(credOS.user)) {
        Logger(ERROR, MD_NM_SVR, "the client <%s> has no admin permission!", credOS.user);
        return PWR_ERR_NOT_AUTHED;
    }
    strncpy(userName, credOS.user, PWR_MAX_ELEMENT_NAME_LEN);
    return PWR_SUCCESS;
}

static PWR_COM_EventInfo* CreateEventInfo(PWR_COM_EVT_TYPE eventType, const void *info, uint32_t len)
{
    size_t eventInfoLen = sizeof(PWR_COM_EventInfo) + len;
    PWR_COM_EventInfo *eventInfo = (PWR_COM_EventInfo *)malloc(eventInfoLen);
    if (!eventInfo) {
        return NULL;
    }

    bzero(eventInfo, sizeof(eventInfoLen));
    GetCurFullTime(eventInfo->ctime, PWR_MAX_TIME_LEN);
    eventInfo->eventType = eventType;
    eventInfo->infoLen = len;
    memcpy(eventInfo->info, info, len);
    return eventInfo;
}

static int DoSendEventToClient(const int dstFd, const uint32_t sysId, char *data, uint32_t len);
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

    struct ucred credSocket;
    if (getsockopt(newClientFd, SOL_SOCKET, SO_PEERCRED, &credSocket, &socklen) < 0) {
        Logger(ERROR, MD_NM_SVR, "get sock options failed");
        close(newClientFd);
        return;
    }

    PwrClient client = {0};
    client.fd = newClientFd;
    client.sysId = credSocket.pid;
    int ret = PassCredVerification(&credSocket, client.userName);
    if (ret == PWR_ERR_NOT_AUTHED) {
        Logger(ERROR, MD_NM_CRED, "credentials verification failed");
        const char *info = "Server has closed connection. This client has no admin permission.";
        /* eventData should be release in the function that uses it */
        PWR_COM_EventInfo *eventInfo = CreateEventInfo(PWR_COM_EVTTYPE_CRED_FAILED, info, strlen(info) + 1);
        if (!eventInfo) {
            Logger(ERROR, MD_NM_SVR, "Create event failed.");
            close(newClientFd);
            return;
        }

        DoSendEventToClient(newClientFd, credSocket.pid, (char *)eventInfo,
            sizeof(PWR_COM_EventInfo) + strlen(info) + 1);
        close(newClientFd);
        return;
    } else if (ret == PWR_ERR_COMMON) {
        Logger(ERROR, MD_NM_CRED, "credentials verification failed with common error");
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

static void CleanClientResource(PwrClient clients[], int idx)
{
    if (idx < 0 || idx >= MAX_CLIENT_NUM) {
        Logger(ERROR, MD_NM_SVR, "Invalid client index %d", idx);
        return;
    }
    CleanControlAuth(clients[idx].sysId);
    CleanDataCollTaskByClient(clients[idx].sysId);
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
            Logger(INFO, MD_NM_SVR, "connection closed !");
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
    if (!msg) {
        return;
    }
    bzero(msg, sizeof(PwrMsg));
    if (ReadMsg(msg, sizeof(PwrMsg), dstFd, clientIdx) != PWR_SUCCESS) {
        free(msg);
        return;
    }
    Logger(DEBUG, MD_NM_SVR, "Receive msg. opt:%d,sysId:%d, seqId:%d",
        msg->head.optType, msg->head.sysId, msg->head.seqId);

    if (msg->head.dataLen > 0) {
        char *msgcontent = malloc(msg->head.dataLen);
        if (!msgcontent) {
            free(msg);
            return;
        }
        bzero(msgcontent, msg->head.dataLen);
        if (ReadMsg(msgcontent, msg->head.dataLen, dstFd, clientIdx) != PWR_SUCCESS) {
            free(msg);
            free(msgcontent);
            return;
        }
        msg->data = msgcontent;
    } else {
        msg->data = NULL;
    }

    if (msg->head.msgType != MT_REQ) {
        ReleasePwrMsg(&msg); // the server accept request msg only.
        return;
    }

    if (IsFullBuffer(&g_recvBuff)) {
      Logger(WARNING, MD_NM_SVR,
             "Receive buffer is full, opt:%d, sysId:%d, seqId:%d",
             msg->head.optType, msg->head.sysId, msg->head.seqId);
      SendRspToClient(msg, PWR_ERR_MSG_BUFFER_FULL, NULL, 0);
      ReleasePwrMsg(&msg);
      return;
    }

    if (msg->head.sysId != (uint32_t)g_pwrClients[clientIdx].sysId) {
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
    ssize_t sendLen;
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
            Logger(INFO, MD_NM_SVR, "connection closed !");
            CleanClientResource(g_pwrClients, GetIdxByFd(g_pwrClients, dstFd));
            return PWR_ERR_DISCONNECTED;
        }
        leftLen -= sendLen;
        wrLen += sendLen;
    }
    return PWR_SUCCESS;
}

static void DoSendMsgToClient(int dstFd, PwrMsg *msg)
{
    static char data[MAX_DATA_SIZE];
    size_t len = sizeof(PwrMsg) + msg->head.dataLen;
    memcpy(data, msg, sizeof(PwrMsg));

    if (len <= MAX_DATA_SIZE) {
        if (msg->data && msg->head.dataLen > 0) {
            memcpy(data + sizeof(PwrMsg), msg->data, msg->head.dataLen);
        }
        WriteMsg(data, len, dstFd);
    } else {
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

static int DoSendEventToClient(const int dstFd, const uint32_t sysId, char *data, uint32_t len)
{
    if (!data && len != 0) {
        return PWR_ERR_INVALIDE_PARAM;
    }

    PwrMsg *event = (PwrMsg *)malloc(sizeof(PwrMsg));
    if (!event) {
        Logger(ERROR, MD_NM_SVR, "Malloc failed");
        free(data);
        return PWR_ERR_SYS_EXCEPTION;
    }

    bzero(event, sizeof(PwrMsg));
    int res = GenerateEventMsg(event, sysId, data, len);
    if (res != PWR_SUCCESS) {
        Logger(ERROR, MD_NM_SVR, "Generate event msg failed, result:%d", res);
        free(data);
        data = NULL;
        ReleasePwrMsg(&event);
        return res;
    }

    DoSendMsgToClient(dstFd, event);
    Logger(INFO, MD_NM_SVR, "Send event to client. sysId: %d", sysId);
    ReleasePwrMsg(&event);  // This will free(data)
    return PWR_SUCCESS;
}

static void ProcessSendMsgToClient(void)
{
    // Read msg from buffer and send.
    while (!IsEmptyBuffer(&g_sendBuff)) {
        PwrMsg *msg = PopFromBufferHead(&g_sendBuff);
        if (!msg) {
            continue;
        }

        int dstFd = GetFdBySysId(g_pwrClients, msg->head.sysId);
        if (dstFd == INVALID_FD) {
            ReleasePwrMsg(&msg);
            continue;
        }
        DoSendMsgToClient(dstFd, msg);
        Logger(DEBUG, MD_NM_SVR, "Send msg. opt:%d, sysId:%d, seqId:%d, rspCode:%d",
            msg->head.optType, msg->head.sysId, msg->head.seqId, msg->head.rspCode);
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
    (void)none; // avoid unused parameter warning
    fd_set recvFdSet;
    int maxFd = INVALID_FD;
    struct timeval tv;
    InitPwrClient(g_pwrClients);
    while (g_sockProcThread.keepRunning) {
        ProcessSendMsgToClient();

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

        int ret = select(maxFd + 1, &recvFdSet, NULL, NULL, &tv);
        if (ret <= 0) {
            continue;
        }

        if (FD_ISSET(g_listenFd, &recvFdSet)) { // new connection
            AcceptConnection();
        }

        for (int i = 0; i < MAX_CLIENT_NUM; i++) {
            if (g_pwrClients[i].fd != INVALID_FD && FD_ISSET(g_pwrClients[i].fd, &recvFdSet)) {
                // new msg or event
                ProcessRecvMsgFromClient(i);
            }
        }
    } // while

    CloseAllConnections(g_pwrClients);

    return NULL;
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
    {CPU_SET_FREQ_RANGE, SetCpuFreqRange},
    {CPU_GET_IDLE_INFO, GetCpuIdleInfo},
    {CPU_GET_IDLE_GOV, GetCpuIdleGov},
    {CPU_SET_IDLE_GOV, SetCpuIdleGov},
    {CPU_GET_DMA_LATENCY, GetCpuDmaLatency},
    {CPU_SET_DMA_LATENCY, SetCpuDmaLatency},
    {PROC_QUERY_PROCS, ProcQueryProcs},
    {PROC_GET_WATT_STATE, ProcGetWattState},
    {PROC_SET_WATT_STATE, ProcSetWattState},
    {PROC_SET_WATT_FIRST_DOMAIN, ProcSetWattFirstDomain},
    {PROC_GET_WATT_ARRTS, procGetWattAttrs},
    {PROC_SET_WATT_ARRTS, ProcSetWattAttrs},
    {PROC_GET_WATT_PROCS, ProcGetWattProcs},
    {PROC_ADD_WATT_PROCS, ProcAddWattProcs},
    {PROC_DEL_WATT_PROCS, ProcDelWattProcs},
    {PROC_GET_SMART_GRID_STATE, ProcGetSmartGridState},
    {PROC_SET_SMART_GRID_STATE, ProcSetSmartGridState},
    {PROC_GET_SMART_GRID_PROCS, ProcGetSmartGridProcs},
    {PROC_SET_SMART_GRID_PROCS_LEVEL, ProcSetSmartGridProcsLevel},
    {PROC_GET_SMART_GRID_GOV, ProcGetSmartGridGov},
    {PROC_SET_SMART_GRID_GOV, ProcSetSmartGridGov},
    {PROC_GET_SERVICE_STATE, ProcGetServiceState},
    {PROC_SET_SERVICE_STATE, ProcSetServiceState},
    {HBM_GET_SYS_STATE, GetHbmSysState},
    {HBM_SET_ALL_POWER_STATE, SetHbmAllPowerState},
};

static void ProcessReqMsg(PwrMsg *req)
{
    Logger(DEBUG, MD_NM_SVR, "Start processing msg. sysId:%d, optType:%d, seqId:%d",
        req->head.sysId, req->head.optType, req->head.seqId);
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
    (void)none; // avoid unused parameter warning
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

    return NULL;
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
    return PWR_SUCCESS;
}

int SendRspMsg(PwrMsg *rsp)
{
    return AddToBufferTail(&g_sendBuff, rsp);
}

int SendEventToClient(uint32_t sysId, PWR_COM_EVT_TYPE type, void *info, uint32_t infoLen)
{
    PWR_COM_EventInfo *eventInfo = CreateEventInfo(type, info, infoLen);
    if (!eventInfo) {
        Logger(ERROR, MD_NM_SVR, "Create event failed.");
        return PWR_ERR_SYS_EXCEPTION;
    }
    int fd = GetFdBySysId(g_pwrClients, sysId);
    return DoSendEventToClient(fd, sysId, (char *)eventInfo, sizeof(PWR_COM_EventInfo) + infoLen);
}

static const char INTERNAL_USER[] = "eagle";
int IsInternalUser(uint32_t sysId)
{
    const char *name = GetUserNameBySysId(g_pwrClients, sysId);
    if (name && strcmp(INTERNAL_USER, name) == 0) {
        return PWR_TRUE;
    }
    return PWR_FALSE;
}
