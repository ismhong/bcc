// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Realtek, Inc. All rights reserved. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "linuxfiletop.h"

#ifndef S_IFMT
#define S_IFMT 00170000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

#define READ_PARENT_DIR_CALL(N) \
	read_parent_dir(&current_dentry, info.file_dir##N);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct info_t);
	__type(value, struct val_t);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} total_read_bytes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} total_write_bytes SEC(".maps");

volatile const __u32 targ_pid = 0;
volatile const __u32 targ_tid = 0;
volatile const bool all_files = false;

const struct info_t *unused __attribute__((unused));
const struct val_t *unused_val __attribute__((unused));

static void read_parent_dir(struct dentry **dentry, char *target)
{
	struct dentry *parent_dentry = BPF_CORE_READ(*dentry, d_parent);

	if (parent_dentry)
	{
		*dentry = parent_dentry;
		bpf_probe_read_kernel_str(target, DNAME_INLINE_LEN,
					BPF_CORE_READ(*dentry, d_name.name));
	}
}

static int do_entry(struct pt_regs *ctx, bool is_read)
{
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	size_t count = (size_t)PT_REGS_PARM3(ctx);

	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 pid = id;

	if (targ_pid && tgid != targ_pid)
		return 0;
	if (targ_tid && pid != targ_tid)
		return 0;

	struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	umode_t mode = BPF_CORE_READ(inode, i_mode);

	if (!all_files && !S_ISREG(mode))
		return 0;

	struct qstr d_name = BPF_CORE_READ(de, d_name);

	if (d_name.len == 0)
		return 0;

	struct info_t info = {};

	info.pid = tgid;
	info.tid = pid;
	info.inode = BPF_CORE_READ(inode, i_ino);
	struct super_block *sb = BPF_CORE_READ(inode, i_sb);

	info.dev = BPF_CORE_READ(sb, s_dev);
	info.rdev = BPF_CORE_READ(inode, i_rdev);

	bpf_get_current_comm(&info.comm, sizeof(info.comm));
	info.name_len = d_name.len;
	bpf_probe_read_kernel_str(&info.name, sizeof(info.name), d_name.name);

	struct file_system_type *stype = BPF_CORE_READ(sb, s_type);

	bpf_probe_read_kernel_str(&info.fs_type, sizeof(info.fs_type),
				BPF_CORE_READ(stype, name));

	info.dev_major = BPF_CORE_READ(sb, s_dev) >> 20;
	info.dev_minor = BPF_CORE_READ(sb, s_dev) & ((1 << 20) - 1);

	struct dentry *current_dentry = de;

#if MAX_DIR_DEPTH > 0
	READ_PARENT_DIR_CALL(1)
#endif
#if MAX_DIR_DEPTH > 1
	READ_PARENT_DIR_CALL(2)
#endif
#if MAX_DIR_DEPTH > 2
	READ_PARENT_DIR_CALL(3)
#endif
#if MAX_DIR_DEPTH > 3
	READ_PARENT_DIR_CALL(4)
#endif
#if MAX_DIR_DEPTH > 4
	READ_PARENT_DIR_CALL(5)
#endif
#if MAX_DIR_DEPTH > 5
	READ_PARENT_DIR_CALL(6)
#endif
#if MAX_DIR_DEPTH > 6
	READ_PARENT_DIR_CALL(7)
#endif
#if MAX_DIR_DEPTH > 7
	READ_PARENT_DIR_CALL(8)
#endif

	if (S_ISREG(mode))
	{
		info.type = 'R';
	} else if (S_ISSOCK(mode))
	{
		info.type = 'S';
	} else
	{
		info.type = 'O';
	}

	if (de)
	{
		struct val_t *valp;
		struct val_t zero = {};

		valp = bpf_map_lookup_elem(&counts, &info);
		if (!valp) {
			bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
			valp = bpf_map_lookup_elem(&counts, &info);
			if (!valp)
				return 0;
		}

		int map_idx = 0;
		__u64 *total_val;
		if (is_read) {
			__sync_fetch_and_add(&valp->reads, 1);
			__sync_fetch_and_add(&valp->rbytes, count);
			total_val = bpf_map_lookup_elem(&total_read_bytes, &map_idx);
			if (total_val)
				*total_val += count;
		} else {
			__sync_fetch_and_add(&valp->writes, 1);
			__sync_fetch_and_add(&valp->wbytes, count);
			total_val = bpf_map_lookup_elem(&total_write_bytes, &map_idx);
			if (total_val)
				*total_val += count;
		}
	}
	return 0;
}

SEC("kprobe/vfs_read")
int trace_read_entry(struct pt_regs *ctx)
{
	return do_entry(ctx, true);
}

SEC("kprobe/vfs_write")
int trace_write_entry(struct pt_regs *ctx)
{
	return do_entry(ctx, false);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
