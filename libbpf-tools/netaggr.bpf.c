/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2021, Realtek Semiconductor Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   * Neither the name of the Realtek nor the names of its contributors may
 *     be used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "netaggr.h"
#include "maps.bpf.h"

const volatile bool extension = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct aggr_key);
	__type(value, struct info);
} gro SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct aggr_key);
	__type(value, struct info);
} gso SEC(".maps");

static struct info zero;

#define TP_DATA_LOC_READ_STR(dst, field, length)                               \
	do {                                                                   \
	    unsigned short __offset = ctx->__data_loc_##field & 0xFFFF;        \
	    bpf_probe_read_str((void *)dst, length, (char *)ctx + __offset);   \
	} while (0)

SEC("tracepoint/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
	struct aggr_key key = {};
	struct info *info;

	TP_DATA_LOC_READ_STR(&key.name, name, sizeof(key.name));
	info = bpf_map_lookup_or_try_init(&gro, &key, &zero);
	if (!info)
		return 0;

	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	struct napi_gro_cb *grocb = (struct napi_gro_cb *)BPF_CORE_READ(skb, cb);
	u16 gro_segs = BPF_CORE_READ(grocb, count);
	if (gro_segs >= MAX_SLOTS)
		gro_segs = MAX_SLOTS - 1;

	__sync_fetch_and_add(&info->slots[gro_segs], 1);
	if (extension) {
		__sync_fetch_and_add(&info->counts, 1);
		__sync_fetch_and_add(&info->total, gro_segs);
	}
	return 0;
}

SEC("tracepoint/net/net_dev_start_xmit")
int handle_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx)
{
	struct aggr_key key = {};
	struct info *info;

	TP_DATA_LOC_READ_STR(&key.name, name, sizeof(key.name));
	info = bpf_map_lookup_or_try_init(&gso, &key, &zero);
	if (!info)
		return 0;

	u16 gso_segs = ctx->gso_segs;
	if (gso_segs >= MAX_SLOTS)
		gso_segs = MAX_SLOTS - 1;

	__sync_fetch_and_add(&info->slots[gso_segs], 1);
	if (extension) {
		__sync_fetch_and_add(&info->counts, 1);
		__sync_fetch_and_add(&info->total, gso_segs);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
