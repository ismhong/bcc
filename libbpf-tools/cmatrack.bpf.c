// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cmatrack.h"
#include "bits.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct entry_data_t {
	bool range_mode;
	union {
		struct {
			unsigned long count;
			unsigned long start_pfn;
			unsigned long end_pfn;
		} range;
		struct {
			u64 ts;
			u32 count;
			u32 align;
		} alloc;
	};
};

struct pid_migrate_key_t {
	u32 pid;
};

struct pid_migrate_data_t {
	u32 succeeded;
	u32 failed;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct entry_data_t);
} start_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct file_key_t);
	__type(value, struct file_name_t);
} file_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pid_migrate_key_t);
	__type(value, struct pid_migrate_data_t);
} pid_migrate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pid_ino_file_key_t);
	__type(value, struct pid_ino_file_name_t);
} pid_ino_file_map SEC(".maps");

const volatile bool range_mode = false;

SEC("kprobe/cma_alloc")
int BPF_KPROBE(cma_alloc_entry, struct cma *cma, unsigned long count,
		unsigned int align)
{
	if (range_mode)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t data = {};

	data.range_mode = false;
	data.alloc.ts = bpf_ktime_get_ns();
	data.alloc.count = count;
	data.alloc.align = align;

	bpf_map_update_elem(&start_hash, &pid, &data, BPF_ANY);

	return 0;
}

SEC("kretprobe/cma_alloc")
int BPF_KRETPROBE(cma_alloc_return, struct page *ret)
{
	if (range_mode)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;
	struct event *e;

	entry_data = bpf_map_lookup_elem(&start_hash, &pid);
	if (!entry_data)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->pid = pid;
	e->tgid = pid_tgid >> 32;
	e->range_mode = false;
	e->alloc.duration_ns = bpf_ktime_get_ns() - entry_data->alloc.ts;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->alloc.count = entry_data->alloc.count;
	e->alloc.align = entry_data->alloc.align;
	e->fail = (ret == NULL);

	struct pid_migrate_key_t pid_migrate_key = { .pid = pid };
	struct pid_migrate_data_t *pid_migrate_data_p;

	pid_migrate_data_p = bpf_map_lookup_elem(&pid_migrate_map, &pid_migrate_key);
	if (pid_migrate_data_p) {
		e->migrate_succeeded = pid_migrate_data_p->succeeded;
		e->migrate_failed = pid_migrate_data_p->failed;
		bpf_map_delete_elem(&pid_migrate_map, &pid_migrate_key);
	} else {
		e->migrate_succeeded = 0;
		e->migrate_failed = 0;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&start_hash, &pid);
	return 0;
}

SEC("kprobe/alloc_contig_range")
int BPF_KPROBE(alloc_contig_range_entry, unsigned long start, unsigned long end)
{
	if (!range_mode)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t data = {};

	data.range_mode = true;
	data.range.start_pfn = start;
	data.range.end_pfn = end;
	data.range.count = end - start;

	bpf_map_update_elem(&start_hash, &pid, &data, BPF_ANY);

	return 0;
}

SEC("kretprobe/alloc_contig_range")
int BPF_KRETPROBE(alloc_contig_range_return, int ret)
{
	if (!range_mode)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;
	struct event *e;

	entry_data = bpf_map_lookup_elem(&start_hash, &pid);
	if (!entry_data)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->pid = pid;
	e->tgid = pid_tgid >> 32;
	e->range_mode = true;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->range.count = entry_data->range.count;
	e->range.start_pfn = entry_data->range.start_pfn;
	e->range.end_pfn = entry_data->range.end_pfn;
	e->fail = (ret != 0);

	struct pid_migrate_key_t pid_migrate_key = { .pid = pid };
	struct pid_migrate_data_t *pid_migrate_data_p;

	pid_migrate_data_p = bpf_map_lookup_elem(&pid_migrate_map, &pid_migrate_key);
	if (pid_migrate_data_p) {
		e->migrate_succeeded = pid_migrate_data_p->succeeded;
		e->migrate_failed = pid_migrate_data_p->failed;
		bpf_map_delete_elem(&pid_migrate_map, &pid_migrate_key);
	} else {
		e->migrate_succeeded = 0;
		e->migrate_failed = 0;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&start_hash, &pid);
	return 0;
}

static int trace_release_entry(struct inode *inode)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;

	entry_data = bpf_map_lookup_elem(&start_hash, &pid);
	if (entry_data == 0)
		return 0;

	struct pid_ino_file_key_t pid_ino_file_key;
	struct pid_ino_file_name_t *pid_ino_file_name_p;

	pid_ino_file_key.pid = pid;
	pid_ino_file_key.ino = BPF_CORE_READ(inode, i_ino);

	pid_ino_file_name_p = bpf_map_lookup_elem(&pid_ino_file_map, &pid_ino_file_key);
	if (pid_ino_file_name_p == 0) {
		struct pid_ino_file_name_t new_entry = {};
		struct file_key_t file_key = { .ino = pid_ino_file_key.ino };
		struct file_name_t *file_name_p;

		file_name_p = bpf_map_lookup_elem(&file_map, &file_key);
		if (file_name_p)
			bpf_probe_read_kernel(&new_entry.name, sizeof(new_entry.name), &file_name_p->name);

		new_entry.polling_times = 1;
		bpf_map_update_elem(&pid_ino_file_map, &pid_ino_file_key, &new_entry, BPF_ANY);
	} else {
		__sync_fetch_and_add(&pid_ino_file_name_p->polling_times, 1);
	}

	return 0;
}

SEC("kprobe/f2fs_release_page")
int BPF_KPROBE(f2fs_release_page_entry, struct page *page, gfp_t gfp)
{
	return trace_release_entry(BPF_CORE_READ(page, mapping, host));
}

SEC("tp_btf/ext4_releasepage")
int BPF_PROG(ext4_releasepage, struct page *page, gfp_t gfp)
{
	return trace_release_entry(BPF_CORE_READ(page, mapping, host));
}

SEC("tp_btf/ext4_release_folio")
int BPF_PROG(ext4_release_folio, struct folio *folio, gfp_t gfp)
{
	return trace_release_entry(BPF_CORE_READ(&folio->page, mapping, host));
}

SEC("tp_btf/mm_migrate_pages")
int BPF_PROG(mm_migrate_pages, long succeeded, long failed)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid;
	struct entry_data_t *entry_data;

	entry_data = bpf_map_lookup_elem(&start_hash, &pid);
	if (entry_data == 0)
		return 0;

	struct pid_migrate_key_t pid_migrate_key = { .pid = pid };
	struct pid_migrate_data_t *pid_migrate_data_p, zero = {};

	pid_migrate_data_p = bpf_map_lookup_elem(&pid_migrate_map, &pid_migrate_key);
	if (!pid_migrate_data_p) {
		bpf_map_update_elem(&pid_migrate_map, &pid_migrate_key, &zero, BPF_NOEXIST);
		pid_migrate_data_p = bpf_map_lookup_elem(&pid_migrate_map, &pid_migrate_key);
		if (!pid_migrate_data_p)
			return 0;
	}

	__sync_fetch_and_add(&pid_migrate_data_p->succeeded, succeeded);
	__sync_fetch_and_add(&pid_migrate_data_p->failed, failed);

	return 0;
}

static int trace_file_access(struct file *file)
{
	struct file_key_t file_key = {};
	struct file_name_t *file_name_p;
	const unsigned char *name;

	file_key.ino = BPF_CORE_READ(file, f_inode, i_ino);

	file_name_p = bpf_map_lookup_elem(&file_map, &file_key);
	if (file_name_p == 0) {
		struct file_name_t file_name = {};
		name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
		bpf_probe_read_str(&file_name.name, sizeof(file_name.name), (void *)name);
		bpf_map_update_elem(&file_map, &file_key, &file_name, BPF_ANY);
	}
	return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file)
{
	return trace_file_access(file);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file)
{
	return trace_file_access(file);
}

SEC("tp_btf/android_fs_dataread_start")
int BPF_PROG(android_fs_dataread_start, struct file *file, int size)
{
	return trace_file_access(file);
}

SEC("tp_btf/android_fs_datawrite_start")
int BPF_PROG(android_fs_datawrite_start, struct file *file, int size)
{
	return trace_file_access(file);
}
