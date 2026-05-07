// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Realtek, Inc.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcpwin.h"
#include "bits.bpf.h"

const volatile bool targ_snd_wnd = true;
const volatile bool targ_snd_cwnd = true;
const volatile bool targ_rcv_wnd = true;
const volatile bool targ_snd_ssthresh = true;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct hist);
} snd_wnd_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct hist);
} snd_cwnd_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct hist);
} rcv_wnd_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct hist);
} ssthresh_hist SEC(".maps");

static int handle_tcp_rcv_established(struct sock *sk)
{
	struct tcp_sock *ts;
	u64 slot;
	int key = 0;

	ts = (struct tcp_sock *)(sk);

	if (targ_snd_wnd) {
		struct hist *snd_wnd_histp;
		__u32 snd_wnd;

		snd_wnd = BPF_CORE_READ(ts, snd_wnd);
		if (snd_wnd) {
			snd_wnd_histp = bpf_map_lookup_elem(&snd_wnd_hist, &key);
			if (snd_wnd_histp) {
				slot = log2l(snd_wnd);
				if (slot >= MAX_SLOTS)
					slot = MAX_SLOTS - 1;
				__sync_fetch_and_add(&snd_wnd_histp->slots[slot], 1);
			}
		}
	}

	if (targ_snd_cwnd) {
		struct hist *snd_cwnd_histp;
		__u32 snd_cwnd;

		snd_cwnd = BPF_CORE_READ(ts, snd_cwnd);
		if (snd_cwnd) {
			snd_cwnd_histp = bpf_map_lookup_elem(&snd_cwnd_hist, &key);
			if (snd_cwnd_histp) {
				slot = log2l(snd_cwnd);
				if (slot >= MAX_SLOTS)
					slot = MAX_SLOTS - 1;
				__sync_fetch_and_add(&snd_cwnd_histp->slots[slot], 1);
			}
		}
	}

	if (targ_rcv_wnd) {
		struct hist *rcv_wnd_histp;
		__u32 rcv_wnd;

		rcv_wnd = BPF_CORE_READ(ts, rcv_wnd);
		if (rcv_wnd) {
			rcv_wnd_histp = bpf_map_lookup_elem(&rcv_wnd_hist, &key);
			if (rcv_wnd_histp) {
				slot = log2l(rcv_wnd);
				if (slot >= MAX_SLOTS)
					slot = MAX_SLOTS - 1;
				__sync_fetch_and_add(&rcv_wnd_histp->slots[slot], 1);
			}
		}
	}

	if (targ_snd_ssthresh) {
		struct hist *ssthresh_histp;
		__u32 snd_ssthresh;

		snd_ssthresh = BPF_CORE_READ(ts, snd_ssthresh);
		if (snd_ssthresh) {
			ssthresh_histp = bpf_map_lookup_elem(&ssthresh_hist, &key);
			if (ssthresh_histp) {
				slot = log2l(snd_ssthresh);
				if (slot >= MAX_SLOTS)
					slot = MAX_SLOTS - 1;
				__sync_fetch_and_add(&ssthresh_histp->slots[slot], 1);
			}
		}
	}

	return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";