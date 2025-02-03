/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPTOP_H
#define __TCPTOP_H

#define TASK_COMM_LEN 16

struct ip_key_t {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__u32 pid;
	char name[TASK_COMM_LEN];
	__u16 lport;
	__u16 dport;
	__u16 family;
};

struct traffic_t {
	size_t sent;
	size_t received;
};

#endif /* __TCPTOP_H */
