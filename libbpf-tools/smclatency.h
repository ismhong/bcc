// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SMCLATENCY_H
#define __SMCLATENCY_H

#define MAX_CPU_NR 256
#define HIST_SLOTS 27

struct cpu_stat {
	char name[32];
	long long user;
	long long nice;
	long long system;
	long long idle;
	long long iowait;
	long long irq;
	long long softirq;
	long long steal;
	long long guest;
	long long guest_nice;
};

#endif /* __SMCLATENCY_H */
