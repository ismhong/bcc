#ifndef __PAGEALLOCTOP_H
#define __PAGEALLOCTOP_H

#define TASK_COMM_LEN 16

struct page_alloc_stat {
	__u64 movable_size;
	__u64 unmovable_size;
	__u32 tgid;
};

#endif /* __PAGEALLOCTOP_H */
