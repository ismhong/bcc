// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __ARGDIST_H
#define __ARGDIST_H

#include <stdbool.h>

#define MAX_SPEC_LEN 512
#define MAX_PROBES 32
#define MAX_EXPRS 1
#define MAX_SLOTS 32

enum arg_source {
	ARG_NONE,
	ARG1,
	ARG2,
	ARG3,
	ARG4,
	ARG5,
	ARG_RET,
	ARG_PID,
	ARG_LATENCY,
	ARG_CONST_1,
};

enum predicate_op {
	PRED_NONE,
	PRED_EQ,
	PRED_NEQ,
	PRED_GT,
	PRED_LT,
	PRED_GE,
	PRED_LE,
};

struct expr {
	__u8 source;
	__u8 is_member;
	__u64 offset;
	__u64 size;
	__u8 op; // enum predicate_op
	__u64 val;
};

struct probe_config {
	__u32 id;
	__u8 is_hist;
	__u8 is_kretprobe;
	struct expr exprs[MAX_EXPRS];
	__u8 expr_count;
	struct expr filter;
};

struct hist_key {
	__u64 probe_id;
	__u64 slot;
};

struct freq_key {
	__u64 probe_id;
	__u64 value;
};

struct active_probe {
	__u64 ip;
	__u64 entry_ts;
};

#endif /* __ARGDIST_H */
