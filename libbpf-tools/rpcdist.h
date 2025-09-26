/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RPCDIST_H
#define __RPCDIST_H

#define MAX_ENTRIES 10240
#define MAX_SLOTS 26

struct hist_key {
	__u64 key;
	__u64 slot;
};

struct rpc_info {
	__u64 programID;
	__u64 procedureID;
	int rpc_num;
	__u64 ts;
};

struct rpc_stats {
	__u64 latency;
	__u64 max_latency;
	__u64 count;
};

#endif /* __RPCDIST_H */
