use aya_ebpf::{
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{map, btf_tracepoint, raw_tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::{BtfTracePointContext, RawTracePointContext},
    EbpfContext,
};

use bcc_box_common::{IrqKey, IrqInfo, MAX_SLOTS};

#[repr(C)]
pub struct irqaction {
    pub handler: *const core::ffi::c_void,
    pub dev_id: *const core::ffi::c_void,
    pub percpu_dev_id: *const core::ffi::c_void,
    pub next: *const irqaction,
    pub thread_fn: *const core::ffi::c_void,
    pub thread: *const core::ffi::c_void,
    pub secondary: *const irqaction,
    pub irq: u32,
    pub flags: u32,
    pub thread_flags: usize,
    pub thread_mask: usize,
    pub name: *const u8,
}

#[map]
static HARDIRQS_START: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static HARDIRQS_INFOS: HashMap<IrqKey, IrqInfo> = HashMap::with_max_entries(256, 0);

#[no_mangle]
static HARDIRQS_TARG_DIST: u8 = 0;
#[no_mangle]
static HARDIRQS_TARG_NS: u8 = 0;
#[no_mangle]
static HARDIRQS_TARG_CPU: i32 = -1;
#[no_mangle]
static HARDIRQS_CPU_MODE: u8 = 0;

fn is_target_cpu() -> bool {
    let targ_cpu = unsafe { core::ptr::read_volatile(&HARDIRQS_TARG_CPU) };
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
    if let Some(val_ptr) = HARDIRQS_START.get_ptr_mut(0) {
        unsafe { *val_ptr = ts; }
    }
    0
}

fn handle_exit(action_ptr: *const irqaction) -> i32 {
    if !is_target_cpu() {
        return 0;
    }

    let tsp = match HARDIRQS_START.get(0) {
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

    let targ_ns = unsafe { core::ptr::read_volatile(&HARDIRQS_TARG_NS) };
    if targ_ns == 0 {
        delta /= 1000;
    }

    let mut ikey = IrqKey {
        name: [0; 32],
        cpu: 0,
    };

    if !action_ptr.is_null() {
        let mut name_ptr: *const u8 = core::ptr::null();
        if let Ok(ptr) = unsafe { bpf_probe_read_kernel(&(*action_ptr).name) } {
            name_ptr = ptr;
        }
        if !name_ptr.is_null() {
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr, &mut ikey.name) };
        }
    }

    let cpu_mode = unsafe { core::ptr::read_volatile(&HARDIRQS_CPU_MODE) };
    if cpu_mode != 0 {
        ikey.cpu = unsafe { bpf_get_smp_processor_id() };
    }

    let targ_dist = unsafe { core::ptr::read_volatile(&HARDIRQS_TARG_DIST) };
    if let Some(info_ptr) = HARDIRQS_INFOS.get_ptr_mut(&ikey) {
        unsafe {
            (*info_ptr).count += 1;
            if targ_dist == 0 {
                (*info_ptr).total_time += delta;
                if delta > (*info_ptr).max_time {
                    (*info_ptr).max_time = delta;
                }
            } else {
                let mut slot = log2l(delta) as usize;
                if slot >= MAX_SLOTS {
                    slot = MAX_SLOTS - 1;
                }
                (*info_ptr).slots[slot] += 1;
            }
        }
    } else {
        let mut info = IrqInfo {
            count: 1,
            total_time: 0,
            max_time: 0,
            slots: [0; MAX_SLOTS],
        };
        if targ_dist == 0 {
            info.total_time = delta;
            info.max_time = delta;
        } else {
            let mut slot = log2l(delta) as usize;
            if slot >= MAX_SLOTS {
                slot = MAX_SLOTS - 1;
            }
            info.slots[slot] = 1;
        }
        let _ = HARDIRQS_INFOS.insert(&ikey, &info, 0);
    }

    0
}

#[btf_tracepoint(function = "irq_handler_entry")]
pub fn irq_handler_entry_btf(_ctx: BtfTracePointContext) -> i32 {
    handle_entry()
}

#[btf_tracepoint(function = "irq_handler_exit")]
pub fn irq_handler_exit_btf(ctx: BtfTracePointContext) -> i32 {
    let action_ptr: *const irqaction = unsafe { ctx.arg(1) };
    handle_exit(action_ptr)
}

#[raw_tracepoint(tracepoint = "irq_handler_entry")]
pub fn irq_handler_entry(_ctx: RawTracePointContext) -> i32 {
    handle_entry()
}

#[raw_tracepoint(tracepoint = "irq_handler_exit")]
pub fn irq_handler_exit(ctx: RawTracePointContext) -> i32 {
    let args = ctx.as_ptr() as *const u64;
    let action_ptr = unsafe { *args.add(1) } as *const irqaction;
    handle_exit(action_ptr)
}
