use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{map, kprobe, kretprobe},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};

use bcc_box_common::{OpensnoopEvent, TASK_COMM_LEN, PATH_MAX};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtRegsArm64 {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenArgs {
    pub flags: i32,
    pub mode: u32,
    pub fname: [u8; PATH_MAX],
}

#[map]
static START: HashMap<u32, OpenArgs> = HashMap::with_max_entries(10240, 0);

#[map]
static EVENTS: PerfEventArray<OpensnoopEvent> = PerfEventArray::new(0);

#[no_mangle]
static OPENSNOOP_TARG_PID: u32 = 0;
#[no_mangle]
static OPENSNOOP_TARG_TGID: u32 = 0;
#[no_mangle]
static OPENSNOOP_TARG_UID: u32 = 0xFFFFFFFF; // INVALID_UID
#[no_mangle]
static OPENSNOOP_TARG_FAILED: u8 = 0;

#[kprobe]
pub fn opensnoop_enter(ctx: ProbeContext) -> i32 {
    let regs_ptr = ctx.as_ptr() as *const PtRegsArm64;

    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    let targ_tgid = unsafe { core::ptr::read_volatile(&OPENSNOOP_TARG_TGID) };
    let targ_pid = unsafe { core::ptr::read_volatile(&OPENSNOOP_TARG_PID) };
    let targ_uid = unsafe { core::ptr::read_volatile(&OPENSNOOP_TARG_UID) };

    if targ_tgid != 0 && targ_tgid != tgid {
        return 0;
    }
    if targ_pid != 0 && targ_pid != pid {
        return 0;
    }
    if targ_uid != 0xFFFFFFFF {
        let uid = bpf_get_current_uid_gid() as u32;
        if targ_uid != uid {
            return 0;
        }
    }

    // 1. Get the value of x0, which is the pointer to user regs
    let mut user_regs_ptr: *const PtRegsArm64 = core::ptr::null();
    unsafe {
        if let Ok(ptr) = bpf_probe_read_kernel(&(*regs_ptr).regs[0] as *const u64 as *const *const PtRegsArm64) {
            user_regs_ptr = ptr;
        }
    }

    if user_regs_ptr.is_null() {
        return 0;
    }

    let mut filename_ptr: *const u8 = core::ptr::null();
    let mut flags: i32 = 0;
    let mut mode: u32 = 0;

    unsafe {
        // Read real arguments from user_regs
        // regs[1] corresponds to x1 (filename)
        if let Ok(ptr) = bpf_probe_read_kernel(&(*user_regs_ptr).regs[1] as *const u64 as *const *const u8) {
            filename_ptr = ptr;
        }
        // regs[2] corresponds to x2 (flags)
        if let Ok(f) = bpf_probe_read_kernel(&(*user_regs_ptr).regs[2] as *const u64 as *const i32) {
            flags = f;
        }
        // regs[3] corresponds to x3 (mode)
        if let Ok(m) = bpf_probe_read_kernel(&(*user_regs_ptr).regs[3] as *const u64 as *const u32) {
            mode = m;
        }
    }

    let mut open_args = OpenArgs {
        flags,
        mode,
        fname: [0; PATH_MAX],
    };

    // Read userspace string to open_args.fname
    if !filename_ptr.is_null() {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr, &mut open_args.fname)
        };
    }

    let _ = START.insert(&pid, &open_args, 0);
    0
}

#[kretprobe]
pub fn opensnoop_exit(ctx: RetProbeContext) -> i32 {
    // Directly read the return value via x0 register (offset 0) to avoid offset compatibility issues in aya-ebpf embedded bindings on aarch64
    let ret = unsafe {
        let regs = ctx.as_ptr() as *const i64;
        bpf_probe_read_kernel(regs).unwrap_or(-1) as i32
    };

    let targ_failed = unsafe { core::ptr::read_volatile(&OPENSNOOP_TARG_FAILED) };
    if targ_failed != 0 && ret >= 0 {
        return 0;
    }

    let id = bpf_get_current_pid_tgid();
    let pid = id as u32;

    if let Some(open_args) = unsafe { START.get(&pid) } {
        let mut event = OpensnoopEvent {
            ts: unsafe { bpf_ktime_get_ns() },
            pid: (id >> 32) as u32,
            uid: bpf_get_current_uid_gid() as u32,
            ret,
            flags: open_args.flags,
            mode: open_args.mode,
            comm: [0; TASK_COMM_LEN],
            fname: open_args.fname,
        };

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm = comm;
        }

        EVENTS.output(&ctx, &event, 0);

        let _ = START.remove(&pid);
    }

    0
}
