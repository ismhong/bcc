/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LINUXFILETOP_H
#define __LINUXFILETOP_H

#define TASK_COMM_LEN 16
#define DNAME_INLINE_LEN 32
#define MAX_DIR_DEPTH 7
#define FILESYSTEM_TYPE_LEN 32

#define FILE_DIR_DECL(N) char file_dir##N[DNAME_INLINE_LEN];

struct info_t {
	unsigned long inode;
	__u32 dev;
	__u32 rdev;
	__u32 pid;
	__u32 tid;
	__u32 name_len;
	char comm[TASK_COMM_LEN];
	char fs_type[FILESYSTEM_TYPE_LEN];
	char name[DNAME_INLINE_LEN];
	char type;
	unsigned int dev_major;
	unsigned int dev_minor;
#if MAX_DIR_DEPTH > 0
    FILE_DIR_DECL(1)
#endif
#if MAX_DIR_DEPTH > 1
    FILE_DIR_DECL(2)
#endif
#if MAX_DIR_DEPTH > 2
    FILE_DIR_DECL(3)
#endif
#if MAX_DIR_DEPTH > 3
    FILE_DIR_DECL(4)
#endif
#if MAX_DIR_DEPTH > 4
    FILE_DIR_DECL(5)
#endif
#if MAX_DIR_DEPTH > 5
    FILE_DIR_DECL(6)
#endif
#if MAX_DIR_DEPTH > 6
    FILE_DIR_DECL(7)
#endif
#if MAX_DIR_DEPTH > 7
    FILE_DIR_DECL(8)
#endif
} __attribute__((packed));

struct val_t {
	__u64 reads;
	__u64 writes;
	__u64 rbytes;
	__u64 wbytes;
};

#endif /* __LINUXFILETOP_H */
