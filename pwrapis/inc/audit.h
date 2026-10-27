/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: provide audit log service. Audit records answer "who did what
 *              at what time" for the setting interfaces of PowerAPI. The
 *              records are written to an independent audit file, which is not
 *              affected by log level settings.
 * **************************************************************************** */
#ifndef PAPIS_AUDIT_H__
#define PAPIS_AUDIT_H__

#include <stdint.h>
#include "pwrmsg.h"
#include "pwrclient.h"

/* Audit event types */
enum AuditEvtType {
    AUDIT_EVT_CONN = 0, /* client connection established */
    AUDIT_EVT_DISCONN,  /* client connection closed */
    AUDIT_EVT_REQ,      /* setting request received */
    AUDIT_EVT_RSP,      /* setting request finished, result recorded */
};

/**
 * InitAuditLogger - create/open the audit log file.
 * Must be called after InitConfig: the audit file is placed in the same
 * directory as papis.log. Failure does not block the service start.
 */
int InitAuditLogger(void);

/* ClearAuditLogger - close the audit log file. */
void ClearAuditLogger(void);

/* IsAuditOpt - check whether the operation is a setting interface to audit. */
int IsAuditOpt(uint16_t optType);

/* AuditClientConn - record a client connect/disconnect event. */
void AuditClientConn(const PwrClient *client, enum AuditEvtType evt);

/* AuditSettingReq - record who requested which setting with what params.
 * client may be NULL, the identity is then recorded as 'unknown'. */
void AuditSettingReq(const PwrClient *client, const PwrMsg *req);

/* AuditSettingRsp - record the result code of an audited setting request.
 * client may be NULL, the identity is then recorded as 'unknown'. */
void AuditSettingRsp(const PwrClient *client, const PwrMsg *req, int rspCode);

/* AuditCallBegin - announce that the calling thread starts executing the
 * setting request. Lets WRITER events correlate sysfs writes to the exact
 * API call. No-op for non-audited operations. */
void AuditCallBegin(const PwrMsg *req);

/* AuditCallEnd - end the announcement started by AuditCallBegin. */
void AuditCallEnd(void);

/* Writer attribution record handed over by bpfwriter.c. All strings are raw
 * (unescaped); AuditWriterEvent escapes them. */
struct WriterAudit {
    const char *ts;       /* event wall time "YYYY-MM-DD HH:MM:SS.mmm"; NULL = now */
    unsigned int uid;     /* real uid of the writing process */
    int pid;              /* tgid of the writing process */
    int tid;              /* tid of the writing thread */
    const char *comm;     /* writer comm */
    const char *file;     /* resolved write target path */
    const char *value;    /* captured write buffer, NUL-terminated */
    const char *exe;      /* /proc/<pid>/exe, NULL when unavailable */
    const char *cmd;      /* flattened /proc/<pid>/cmdline, NULL when unavailable */
    const char *userName; /* passwd name for uid, NULL when unavailable */
};

/* AuditWriterEvent - record who wrote to a watched sysfs file, captured by
 * the eBPF writer-attribution observer (bpfwriter.c). Writes issued by the
 * service itself are tagged [WRITER][API] and correlated with the in-flight
 * API call; writes from any other process are tagged [WRITER][OS]. */
void AuditWriterEvent(const struct WriterAudit *wa);

#endif
