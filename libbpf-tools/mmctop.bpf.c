// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mmctop.h"
#include "bits.bpf.h"

#define BIT(nr) (1UL << (nr))

#define MMC_DATA_WRITE      BIT(8)
#define MMC_DATA_READ       BIT(9)
#define EXECUTE_WRITE_TASK 47
#define EXECUTE_READ_TASK 46

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct mmc_request *);
    __type(value, struct mmc_key);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct mmc_key);
    __type(value, struct mmc_value);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} config_map SEC(".maps");

SEC("tracepoint/mmc/mmc_request_start")
int tracepoint_mmc_request_start(struct trace_event_raw_mmc_request_start *ctx)
{
    u32 key = 0;
    struct config *cfg;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0;

    struct mmc_request *mrq = (struct mmc_request *)ctx->mrq;
    u32 cmd = ctx->cmd_opcode;
        u32 cmd_arg = ctx->cmd_arg;
    if (!cmd_arg)
        cmd_arg = ctx->blk_addr;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct mmc_key val = {};

    if (!ctx->cmd_opcode)
        if ((ctx->data_flags & MMC_DATA_WRITE) || (ctx->data_flags & MMC_DATA_READ))
            cmd = (ctx->data_flags & MMC_DATA_WRITE) ? EXECUTE_WRITE_TASK : EXECUTE_READ_TASK;

    if (cfg->filter_cmd != -1 && cmd != cfg->filter_cmd)
        return 0;

    if (cfg->min_blocks > 0 && ctx->blocks < cfg->min_blocks)
        return 0;
    if (cfg->max_blocks != -1 && ctx->blocks > cfg->max_blocks)
        return 0;

    if (cfg->per_pid) {
        val.pid = pid_tgid >> 32;
        val.tid = pid_tgid;
        bpf_get_current_comm(&val.name, sizeof(val.name));
    }

    val.cmd = cmd;
    val.blocks = ctx->blocks;
    val.blksz = ctx->blksz;

    if (cfg->per_cmd_arg)
        val.cmd_arg = cmd_arg;
    else
        val.cmd_arg = 0;

    val.cmd_flags = ctx->cmd_flags;
    val.data_flags = ctx->data_flags;
    val.ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start, &mrq, &val, BPF_ANY);

    return 0;
}

SEC("tracepoint/mmc/mmc_request_done")
int tracepoint_mmc_request_done(struct trace_event_raw_mmc_request_done *ctx)
{
    u32 key = 0;
    struct config *cfg;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0;

    struct mmc_request *mrq = (struct mmc_request *)ctx->mrq;
    struct mmc_key *info_key, key_search = {};
    struct mmc_value *info_val;
    struct mmc_value zero = {};
    u32 cmd;
    u64 delta;

    info_key = bpf_map_lookup_elem(&start, &mrq);
    if (!info_key)
        return 0;

    cmd = info_key->cmd;
    if (cfg->filter_cmd != -1 && cmd != cfg->filter_cmd) {
        bpf_map_delete_elem(&start, &mrq);
        return 0;
    }

    delta = bpf_ktime_get_ns() - info_key->ts;
    info_key->ts = 0;

    u32 blocks = info_key->blocks;
    if (!cfg->per_blocks)
        info_key->blocks = 0;

    key_search = *info_key;
    info_val = bpf_map_lookup_elem(&counts, &key_search);
    if (!info_val) {
        bpf_map_update_elem(&counts, &key_search, &zero, BPF_NOEXIST);
        info_val = bpf_map_lookup_elem(&counts, &key_search);
        if (!info_val)
            goto cleanup;
    }

    if (!cfg->per_blocks)
        info_val->blocks += blocks;

    info_val->delay += delta;
    info_val->io++;
    if (delta > info_val->max)
        info_val->max = delta;
    if (info_val->min == 0 || delta < info_val->min)
        info_val->min = delta;

cleanup:
    bpf_map_delete_elem(&start, &mrq);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
