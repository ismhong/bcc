/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPWIN_H
#define __TCPWIN_H

#define MAX_SLOTS	32

struct hist {
	unsigned int slots[MAX_SLOTS];
};

#endif /* __TCPWIN_H */