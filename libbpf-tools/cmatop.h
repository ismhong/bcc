#ifndef __CMATOP_H
#define __CMATOP_H

#define MAX_ENTRIES 10240

struct cma_alloc_t {
	__u64 total_latency;
	__u64 total_count;
	__u64 max;
	__u64 min;
	__u32 align;
	__u32 success;
	__u32 fail;
	__u32 pad;
};

#endif /* __CMATOP_H */
