use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{map, btf_tracepoint, raw_tracepoint},
    maps::HashMap,
    programs::{BtfTracePointContext, RawTracePointContext},
    EbpfContext,
};

use bcc_box_common::{WqVal, WqKey, WQ_NAME_LEN};

#[map]
static WQLAT_START: HashMap<u64, WqVal> = HashMap::with_max_entries(10240, 0);

#[map]
static WQLAT_HISTS: HashMap<WqKey, u64> = HashMap::with_max_entries(10240, 0);

#[no_mangle]
static WQLAT_TARG_WORKQUEUES: u8 = 0;
#[no_mangle]
static WQLAT_TARG_NS: u8 = 0;
#[no_mangle]
static WQLAT_FILTER_WQNAME: [u8; WQ_NAME_LEN] = [0; WQ_NAME_LEN];

fn log2l(v: u64) -> u64 {
    if v == 0 {
        return 0;
    }
    63 - v.leading_zeros() as u64
}

fn is_filtered_wq(wq_name: &[u8; WQ_NAME_LEN]) -> bool {
    let filter = unsafe { core::ptr::read_volatile(&WQLAT_FILTER_WQNAME) };
    if filter[0] == 0 {
        return false;
    }
    for i in 0..WQ_NAME_LEN {
        if filter[i] != wq_name[i] {
            return true;
        }
        if filter[i] == 0 {
            break;
        }
    }
    false
}

fn handle_queue_work(pwq: *const core::ffi::c_void, work: *const core::ffi::c_void) -> i32 {
    if pwq.is_null() || work.is_null() {
        return 0;
    }

    // Read pwq->wq (at offset 8)
    let wq_ptr: *const core::ffi::c_void = unsafe {
        let wq_addr_ptr = (pwq as *const u8).add(8) as *const *const core::ffi::c_void;
        match bpf_probe_read_kernel(wq_addr_ptr) {
            Ok(ptr) => ptr,
            Err(_) => return 0,
        }
    };

    if wq_ptr.is_null() {
        return 0;
    }

    // Read wq->name (at offset 192)
    let mut wq_name = [0u8; WQ_NAME_LEN];
    unsafe {
        let name_addr_ptr = (wq_ptr as *const u8).add(192);
        if bpf_probe_read_kernel_str_bytes(name_addr_ptr, &mut wq_name).is_err() {
            return 0;
        }
    }

    if is_filtered_wq(&wq_name) {
        return 0;
    }

    let ts = unsafe { bpf_ktime_get_ns() };
    let val = WqVal { wq_name, ts };
    let work_addr = work as u64;

    let _ = WQLAT_START.insert(&work_addr, &val, 0);

    0
}

fn handle_execute_start(work: *const core::ffi::c_void) -> i32 {
    if work.is_null() {
        return 0;
    }

    let work_addr = work as u64;
    let val = match unsafe { WQLAT_START.get(&work_addr) } {
        Some(v) => v,
        None => return 0, // missed start
    };

    let now = unsafe { bpf_ktime_get_ns() };
    if now < val.ts {
        let _ = WQLAT_START.remove(&work_addr);
        return 0;
    }
    let mut delta = now - val.ts;

    let targ_ns = unsafe { core::ptr::read_volatile(&WQLAT_TARG_NS) };
    if targ_ns == 0 {
        delta /= 1000;
    }

    let mut key = WqKey {
        wq_name: [0; WQ_NAME_LEN],
        slot: log2l(delta),
    };

    let targ_workqueues = unsafe { core::ptr::read_volatile(&WQLAT_TARG_WORKQUEUES) };
    if targ_workqueues != 0 {
        key.wq_name = val.wq_name;
    }

    unsafe {
        if let Some(count_ptr) = WQLAT_HISTS.get_ptr_mut(&key) {
            *count_ptr += 1;
        } else {
            let _ = WQLAT_HISTS.insert(&key, &1, 0);
        }
    }

    let _ = WQLAT_START.remove(&work_addr);
    0
}

#[btf_tracepoint(function = "workqueue_queue_work")]
pub fn workqueue_queue_work_btf(ctx: BtfTracePointContext) -> i32 {
    let pwq: *const core::ffi::c_void = unsafe { ctx.arg(1) };
    let work: *const core::ffi::c_void = unsafe { ctx.arg(2) };
    handle_queue_work(pwq, work)
}

#[btf_tracepoint(function = "workqueue_execute_start")]
pub fn workqueue_execute_start_btf(ctx: BtfTracePointContext) -> i32 {
    let work: *const core::ffi::c_void = unsafe { ctx.arg(0) };
    handle_execute_start(work)
}

#[raw_tracepoint(tracepoint = "workqueue_queue_work")]
pub fn workqueue_queue_work(ctx: RawTracePointContext) -> i32 {
    let regs = ctx.as_ptr() as *const u64;
    let pwq = unsafe { *regs.add(1) } as *const core::ffi::c_void;
    let work = unsafe { *regs.add(2) } as *const core::ffi::c_void;
    handle_queue_work(pwq, work)
}

#[raw_tracepoint(tracepoint = "workqueue_execute_start")]
pub fn workqueue_execute_start(ctx: RawTracePointContext) -> i32 {
    let regs = ctx.as_ptr() as *const u64;
    let work = unsafe { *regs } as *const core::ffi::c_void;
    handle_execute_start(work)
}
