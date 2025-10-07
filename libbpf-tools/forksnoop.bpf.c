// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "forksnoop.h"

const volatile pid_t targ_pid = INVALID_PID;
const volatile pid_t targ_tid = INVALID_PID;
const volatile bool snoop_mode = true;
const volatile bool stat_mode = true;
const volatile int targ_event_type = -1;

static const struct event empty_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct task_info);
	__type(value, struct event_count);
} counts SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched_process_fork(struct trace_event_raw_sched_process_fork *args)
{
	struct task_struct *child = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(child, real_parent);

	pid_t ppid = BPF_CORE_READ(parent, tgid);
	pid_t ptid = args->parent_pid;
	pid_t cpid = BPF_CORE_READ(child, tgid);
	pid_t ctid = args->child_pid;

	if (targ_pid != INVALID_PID && ppid != targ_pid && cpid != targ_pid) {
		return 0;
	}
	if (targ_tid != INVALID_PID && ptid != targ_tid && ctid != targ_tid) {
		return 0;
	}
	if (targ_event_type != -1 && targ_event_type != EVENT_FORK)
		return 0;

	if (snoop_mode) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->type = EVENT_FORK;
			e->pid = ppid;
			e->tid = ptid;
			e->ppid = BPF_CORE_READ(parent, real_parent, tgid);
			bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), args->parent_comm);

			e->child_pid = cpid;
			e->child_tid = ctid;
			bpf_probe_read_kernel_str(e->child_comm, sizeof(e->child_comm), args->child_comm);

			bpf_ringbuf_submit(e, 0);
		}
	}

	if (stat_mode) {
		struct task_info info = {};
		info.ppid = BPF_CORE_READ(parent, real_parent, tgid);
		info.pid = ppid;
		info.tid = ptid;

		struct event_count *count, zero = {};
		count = bpf_map_lookup_elem(&counts, &info);
		if (!count) {
			bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
			count = bpf_map_lookup_elem(&counts, &info);
			if (!count)
				return 0;
			bpf_probe_read_kernel_str(&count->comm, sizeof(count->comm), args->parent_comm);
		}
		count->fork++;
		count->total++;
	}

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_process_exit(struct trace_event_raw_sched_process_template *args)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	pid_t pid = BPF_CORE_READ(task, tgid);
	pid_t tid = BPF_CORE_READ(task, pid);
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);

	if (targ_pid != INVALID_PID && pid != targ_pid) {
		return 0;
	}
	if (targ_tid != INVALID_PID && tid != targ_tid) {
		return 0;
	}
	if (targ_event_type != -1 && targ_event_type != EVENT_EXIT)
		return 0;

	if (snoop_mode) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->type = EVENT_EXIT;
			e->pid = pid;
			e->tid = tid;
			e->ppid = ppid;
			bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), task->comm);
			e->duration_ns = bpf_ktime_get_ns() - BPF_CORE_READ(task, start_time);
			bpf_ringbuf_submit(e, 0);
		}
	}

	if (stat_mode) {
		struct task_info info = {};
		info.ppid = ppid;
		info.pid = pid;
		info.tid = tid;

		struct event_count *count, zero = {};
		count = bpf_map_lookup_elem(&counts, &info);
		if (!count) {
			bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
			count = bpf_map_lookup_elem(&counts, &info);
			if (!count)
				return 0;
			bpf_probe_read_kernel_str(&count->comm, sizeof(count->comm), task->comm);
		}
		count->exit++;
		count->total++;
		count->duration = bpf_ktime_get_ns() - BPF_CORE_READ(task, start_time);
	}

	return 0;
}

static __always_inline
int __execve_entry(struct pt_regs *ctx, const char *filename, const char *const *argv, bool is_compat)
{
	pid_t tgid;
	struct event *event;
	struct task_struct *task;
	u64 argp;
	int ret;

	pid_t tid = (pid_t)bpf_get_current_pid_tgid();
	tgid = bpf_get_current_pid_tgid() >> 32;

	if (targ_pid != INVALID_PID && tgid != targ_pid) {
		return 0;
	}
	if (targ_tid != INVALID_PID && tid != targ_tid) {
		return 0;
	}
	if (targ_event_type != -1 && targ_event_type != EVENT_EXEC)
		return 0;

	if (snoop_mode) {
		if (bpf_map_update_elem(&execs, &tid, &empty_event, BPF_NOEXIST))
			return 0;

		event = bpf_map_lookup_elem(&execs, &tid);
		if (!event)
			return 0;

		event->type = EVENT_EXEC;
		event->pid = tgid;
		event->tid = tid;
		task = (struct task_struct*)bpf_get_current_task();
		event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
		event->args_count = 0;
		event->args_size = 0;

		ret = bpf_probe_read_user_str(event->args, ARGSIZE, filename);
		if (ret < 0) {
			bpf_map_delete_elem(&execs, &tid);
			return 0;
		}
		if (ret <= ARGSIZE) {
			event->args_size += ret;
		} else {
			event->args[0] = '\0';
			event->args_size++;
		}

		event->args_count++;
		#pragma unroll
		for (int i = 1; i < MAX_ARGS; i++) {
			u64 argument_size = (is_compat)? 4 : 8;
			u64 argv_addr = (u64)argv + i * argument_size;
			ret = bpf_probe_read_user(&argp, sizeof(argp), (void *)argv_addr);
			if (ret < 0) {
				goto done_snoop;
			}

			if (event->args_size > sizeof(event->args) - ARGSIZE) {
				goto done_snoop;
			}

			argp = (is_compat)? argp & 0xFFFFFFFF : argp;
			if (!argp) {
				goto done_snoop;
			}

			ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, (void *)argp);
			if (ret < 0) {
				goto done_snoop;
			}

			event->args_count++;
			event->args_size += ret;
		}
		done_snoop:
			;
	}

	return 0;
}

SEC("ksyscall/execve")
int BPF_KSYSCALL(execve_entry, const char *filename, const char *const *argv, const char *const *envp)
{
	return __execve_entry(ctx, filename, argv, false);
}

SEC("kprobe/__arm64_compat_sys_execve")
int BPF_KSYSCALL(compat_execve_entry, const char *filename, const char *const *argv, const char *const *envp)
{
	return __execve_entry(ctx, filename, argv, true);
}

static __always_inline
int __execve_exit(void *ctx, int rc)
{
	pid_t tid;
	struct event *event;

	tid = (pid_t)bpf_get_current_pid_tgid();
	pid_t tgid = bpf_get_current_pid_tgid() >> 32;

	if (targ_pid != INVALID_PID && tgid != targ_pid) {
		return 0;
	}
	if (targ_tid != INVALID_PID && tid != targ_tid) {
		return 0;
	}
	if (targ_event_type != -1 && targ_event_type != EVENT_EXEC)
		return 0;

	if (snoop_mode) {
		event = bpf_map_lookup_elem(&execs, &tid);
		if (!event)
			return 0;

		event->retval = rc;
		bpf_get_current_comm(&event->comm, sizeof(event->comm));

		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			bpf_probe_read_kernel(e, sizeof(struct event), event);
			bpf_ringbuf_submit(e, 0);
		}
		bpf_map_delete_elem(&execs, &tid);
	}

	if (stat_mode) {
		struct task_info info = {};
		struct task_struct *task = (struct task_struct*)bpf_get_current_task();
		info.ppid = BPF_CORE_READ(task, real_parent, tgid);
		info.pid = tgid;
		info.tid = tid;

		struct event_count *count, zero = {};
		count = bpf_map_lookup_elem(&counts, &info);
		if (!count) {
			bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
			count = bpf_map_lookup_elem(&counts, &info);
			if (!count)
				return 0;
		}
		bpf_get_current_comm(&count->comm, sizeof(count->comm));
		count->execute++;
		count->total++;
	}

	return 0;
}

SEC("kretsyscall/execve")
int BPF_KRETPROBE(execve_exit, int rc)
{
	return __execve_exit(ctx, rc);
}

SEC("kretprobe/__arm64_compat_sys_execve")
int BPF_KRETPROBE(compat_execve_exit, int rc)
{
	return __execve_exit(ctx, rc);
}

SEC("tracepoint/task/task_rename")
int tracepoint__task_task_rename(struct trace_event_raw_task_rename *args)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	pid_t pid = BPF_CORE_READ(task, tgid);
	pid_t tid = BPF_CORE_READ(task, pid);
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);

	if (targ_pid != INVALID_PID && pid != targ_pid) {
		return 0;
	}
	if (targ_tid != INVALID_PID && tid != targ_tid) {
		return 0;
	}
	if (targ_event_type != -1 && targ_event_type != EVENT_RENAME)
		return 0;

	if (snoop_mode) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->type = EVENT_RENAME;
			e->pid = pid;
			e->tid = tid;
			e->ppid = ppid;
			bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), args->oldcomm);
			bpf_probe_read_kernel_str(e->newcomm, sizeof(e->newcomm), args->newcomm);
			bpf_ringbuf_submit(e, 0);
		}
	}

	if (stat_mode) {
		struct task_info info = {};
		info.ppid = ppid;
		info.pid = pid;
		info.tid = tid;

		struct event_count *count, zero = {};
		count = bpf_map_lookup_elem(&counts, &info);
		if (!count) {
			bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
			count = bpf_map_lookup_elem(&counts, &info);
			if (!count)
				return 0;
			bpf_probe_read_kernel_str(&count->comm, sizeof(count->comm), args->oldcomm);
		}
		count->rename++;
		count->total++;
		bpf_probe_read_kernel_str(&count->newname, sizeof(count->newname), args->newcomm);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
