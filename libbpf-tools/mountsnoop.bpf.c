/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "compat.bpf.h"
#include "mountsnoop.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

static int probe_entry(union sys_arg *sys_arg, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};

	if (target_pid && target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.op = op;

	switch (op) {
	case MOUNT:
	case UMOUNT:
	case FSOPEN:
	case FSCONFIG:
	case FSMOUNT:
	case MOVE_MOUNT:
		__builtin_memcpy(&arg.sys, sys_arg, sizeof(*sys_arg));
		break;
	default:
		goto skip;
	}

	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);
skip:
	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct task_struct *task;
	struct event *eventp;
	struct arg *argp;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	task = (struct task_struct *)bpf_get_current_task();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->op = argp->op;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	eventp->ret = ret;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));

	switch (argp->op) {
	case MOUNT:
		eventp->mount.flags = argp->sys.mount.flags;
		bpf_probe_read_user_str(eventp->mount.src,
					sizeof(eventp->mount.src),
					argp->sys.mount.src);
		bpf_probe_read_user_str(eventp->mount.dest,
					sizeof(eventp->mount.dest),
					argp->sys.mount.dest);
		bpf_probe_read_user_str(eventp->mount.fs,
					sizeof(eventp->mount.fs),
					argp->sys.mount.fs);
		bpf_probe_read_user_str(eventp->mount.data,
					sizeof(eventp->mount.data),
					argp->sys.mount.data);
		break;
	case UMOUNT:
		eventp->umount.flags = argp->sys.umount.flags;
		bpf_probe_read_user_str(eventp->umount.dest,
					sizeof(eventp->umount.dest),
					argp->sys.umount.dest);
		break;
	case FSOPEN:
		eventp->fsopen.flags = argp->sys.fsopen.flags;
		bpf_probe_read_user_str(eventp->fsopen.fs,
					sizeof(eventp->fsopen.fs),
					argp->sys.fsopen.fs);
		break;
	case FSCONFIG:
		eventp->fsconfig.fd = argp->sys.fsconfig.fd;
		eventp->fsconfig.cmd = argp->sys.fsconfig.cmd;
		bpf_probe_read_user_str(eventp->fsconfig.key,
					sizeof(eventp->fsconfig.key),
					argp->sys.fsconfig.key);
		bpf_probe_read_user_str(eventp->fsconfig.value,
					sizeof(eventp->fsconfig.value),
					argp->sys.fsconfig.value);
		eventp->fsconfig.aux = argp->sys.fsconfig.aux;
		break;
	case FSMOUNT:
		eventp->fsmount.fs_fd = argp->sys.fsmount.fs_fd;
		eventp->fsmount.flags = argp->sys.fsmount.flags;
		eventp->fsmount.attr_flags = argp->sys.fsmount.attr_flags;
		break;
	case MOVE_MOUNT:
		eventp->move_mount.from_dfd = argp->sys.move_mount.from_dfd;
		bpf_probe_read_user_str(eventp->move_mount.from_pathname,
					sizeof(eventp->move_mount.from_pathname),
					argp->sys.move_mount.from_pathname);
		eventp->move_mount.to_dfd = argp->sys.move_mount.to_dfd;
		bpf_probe_read_user_str(eventp->move_mount.to_pathname,
					sizeof(eventp->move_mount.to_pathname),
					argp->sys.move_mount.to_pathname);
		break;
	}

	submit_buf(ctx, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("ksyscall/mount")
int BPF_KSYSCALL(mount_entry, const char *source,
                      const char *target, const char *type,
                      const unsigned long flags, const char *data)
{
	union sys_arg arg = {};

	arg.mount.src = source;
	arg.mount.dest = target;
	arg.mount.fs = type;
	arg.mount.flags = flags;
	arg.mount.data = data;

	return probe_entry(&arg, MOUNT);
}

SEC("kretsyscall/mount")
int BPF_KRETPROBE(mount_exit, int rc)
{
	return probe_exit(ctx, rc);
}

SEC("ksyscall/umount")
int BPF_KSYSCALL(umount_entry, const char *target, const int flags)
{
	union sys_arg arg = {};

	arg.umount.dest = target;
	arg.umount.flags = flags;

	return probe_entry(&arg, UMOUNT);
}

SEC("kretsyscall/umount")
int BPF_KRETPROBE(umount_exit, int rc)
{
	return probe_exit(ctx, rc);
}

SEC("ksyscall/fsopen")
int BPF_KSYSCALL(fsopen_entry, char *fs_name, unsigned long flags)
{
	union sys_arg arg = {};

	arg.fsopen.fs = fs_name;
	arg.fsopen.flags = flags;

	return probe_entry(&arg, FSOPEN);
}

SEC("kretsyscall/fsopen")
int BPF_KRETPROBE(fsopen_exit, int rc)
{
	return probe_exit(ctx, rc);
}

SEC("ksyscall/fsconfig")
int BPF_KSYSCALL(fsconfig_entry, int fd, unsigned int cmd,
                      char *key, char *value, int aux)
{
	union sys_arg arg = {};

	arg.fsconfig.fd = fd;
	arg.fsconfig.cmd = cmd;
	arg.fsconfig.key = key;
	arg.fsconfig.value = value;
	arg.fsconfig.aux = aux;

	return probe_entry(&arg, FSCONFIG);
}

SEC("kretsyscall/fsconfig")
int BPF_KRETPROBE(fsconfig_exit, int rc)
{
	return probe_exit(ctx, rc);
}

SEC("ksyscall/fsmount")
int BPF_KSYSCALL(fsmount_entry, unsigned int fs_fd,
                     unsigned int flags, unsigned int attr_flags)
{
	union sys_arg arg = {};

	arg.fsmount.fs_fd = fs_fd;
	arg.fsmount.flags = flags;
	arg.fsmount.attr_flags = attr_flags;

	return probe_entry(&arg, FSMOUNT);
}

SEC("kretsyscall/fsmount")
int BPF_KRETPROBE(fsmount_exit, int rc)
{
	return probe_exit(ctx, rc);
}

SEC("ksyscall/move_mount")
int BPF_KSYSCALL(move_mount_entry, int from_dfd, char *from_pathname,
                        int to_dfd, char *to_pathname,
                        unsigned int flags)
{
	union sys_arg arg = {};

	arg.move_mount.from_dfd = from_dfd;
	arg.move_mount.from_pathname = from_pathname;
	arg.move_mount.to_dfd = to_dfd;
	arg.move_mount.to_pathname = to_pathname;

	return probe_entry(&arg, MOVE_MOUNT);
}

SEC("kretsyscall/move_mount")
int BPF_KRETPROBE(move_mount_exit, int rc)
{
	return probe_exit(ctx, rc);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
