use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_get_smp_processor_id},
    macros::{map, btf_tracepoint, raw_tracepoint},
    maps::PerCpuArray,
    programs::{BtfTracePointContext, RawTracePointContext},
    EbpfContext,
};

use bcc_box_common::{Hist, MAX_SLOTS, NR_SOFTIRQS};

#[map]
static SOFTIRQS_START: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SOFTIRQS_COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(10, 0);

#[map]
static SOFTIRQS_TIME: PerCpuArray<u64> = PerCpuArray::with_max_entries(10, 0);

#[map]
static SOFTIRQS_HISTS: PerCpuArray<Hist> = PerCpuArray::with_max_entries(10, 0);

#[no_mangle]
static SOFTIRQS_TARG_DIST: u8 = 0;
#[no_mangle]
static SOFTIRQS_TARG_NS: u8 = 0;
#[no_mangle]
static SOFTIRQS_TARG_CPU: i32 = -1;

fn is_target_cpu() -> bool {
    let targ_cpu = unsafe { core::ptr::read_volatile(&SOFTIRQS_TARG_CPU) };
    if targ_cpu < 0 {
        return true;
    }
    (unsafe { bpf_get_smp_processor_id() } as i32) == targ_cpu
}

fn log2l(v: u64) -> u64 {
    if v == 0 {
        return 0;
    }
    63 - v.leading_zeros() as u64
}

fn handle_entry() -> i32 {
    if !is_target_cpu() {
        return 0;
    }
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(val_ptr) = SOFTIRQS_START.get_ptr_mut(0) {
        unsafe { *val_ptr = ts; }
    }
    0
}

fn handle_exit(vec_nr: u32) -> i32 {
    if !is_target_cpu() {
        return 0;
    }
    if vec_nr >= NR_SOFTIRQS as u32 {
        return 0;
    }

    let tsp = match SOFTIRQS_START.get(0) {
        Some(p) => p,
        None => return 0,
    };
    if *tsp == 0 {
        return 0;
    }

    let now = unsafe { bpf_ktime_get_ns() };
    if now < *tsp {
        return 0;
    }
    let mut delta = now - *tsp;

    let targ_ns = unsafe { core::ptr::read_volatile(&SOFTIRQS_TARG_NS) };
    if targ_ns == 0 {
        delta /= 1000;
    }

    let targ_dist = unsafe { core::ptr::read_volatile(&SOFTIRQS_TARG_DIST) };
    if targ_dist == 0 {
        if let Some(val_ptr) = SOFTIRQS_COUNTS.get_ptr_mut(vec_nr) {
            unsafe { *val_ptr += 1; }
        }
        if let Some(val_ptr) = SOFTIRQS_TIME.get_ptr_mut(vec_nr) {
            unsafe { *val_ptr += delta; }
        }
    } else {
        if let Some(hist_ptr) = SOFTIRQS_HISTS.get_ptr_mut(vec_nr) {
            let mut slot = log2l(delta) as usize;
            if slot >= MAX_SLOTS {
                slot = MAX_SLOTS - 1;
            }
            unsafe {
                (*hist_ptr).slots[slot] += 1;
            }
        }
    }

    0
}

#[btf_tracepoint(function = "softirq_entry")]
pub fn softirq_entry_btf(_ctx: BtfTracePointContext) -> i32 {
    handle_entry()
}

#[btf_tracepoint(function = "softirq_exit")]
pub fn softirq_exit_btf(ctx: BtfTracePointContext) -> i32 {
    let vec_nr: u32 = unsafe { ctx.arg(0) };
    handle_exit(vec_nr)
}

#[raw_tracepoint(tracepoint = "softirq_entry")]
pub fn softirq_entry(_ctx: RawTracePointContext) -> i32 {
    handle_entry()
}

#[raw_tracepoint(tracepoint = "softirq_exit")]
pub fn softirq_exit(ctx: RawTracePointContext) -> i32 {
    let regs = ctx.as_ptr() as *const u64;
    let vec_nr = unsafe { *regs } as u32;
    handle_exit(vec_nr)
}
