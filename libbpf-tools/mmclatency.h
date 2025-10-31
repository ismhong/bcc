#ifndef __MMCLATENCY_H
#define __MMCLATENCY_H

#define MAX_SLOTS 26 // From mmclatency.py's default histogram size

enum {
	NSEC,
	USEC,
	MSEC,
};

typedef struct cmd_key {
	unsigned long long value;
	unsigned long long slot;
} cmd_key_t;

#endif /* __MMCLATENCY_H */
