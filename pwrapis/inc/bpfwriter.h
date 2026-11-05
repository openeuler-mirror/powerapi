/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * PowerAPI licensed under the Mulan PSL v2.
 * Description: user-space loader and collector for the writer-attribution
 *              eBPF program (P2). Loads bpf_writer.bpf.o, attaches a kprobe
 *              to ksys_write, drains the perf ring buffer and, for each write
 *              that targets a file currently on the drift watch list, emits an
 *              [AUDIT][WRITER] record via AuditWriterEvent(). This gives "who"
 *              for the bypass writes that P1 (drift detection) only flags as
 *              changed.
 *
 *              The loader is best-effort: if BPF is unavailable, permission is
 *              denied, or the .o file is missing, it logs a warning and stays
 *              inert - the service and P1 keep running unaffected.
 * **************************************************************************** */
#ifndef PAPIS_BPFWRITER_H__
#define PAPIS_BPFWRITER_H__

/**
 * InitBpfWriter - load the eBPF program and start the collector thread.
 * Best-effort: never blocks the power service. Requires root (or CAP_BPF);
 * on failure logs a warning and returns success so the service keeps running.
 * Must be called after InitDriftMonitor (uses the drift target list for path
 * correlation) and InitAuditLogger.
 */
int InitBpfWriter(void);

/* ClearBpfWriter - detach the program, close resources, stop the thread. */
void ClearBpfWriter(void);

#endif
