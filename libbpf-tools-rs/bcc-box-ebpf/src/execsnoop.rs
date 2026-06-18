use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes, bpf_probe_read_user, bpf_probe_read_kernel,
    },
    macros::{map, kprobe, kretprobe},
    maps::{HashMap, PerfEventArray, PerCpuArray},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};

use bcc_box_common::{ExecsnoopEvent, TASK_COMM_LEN, ARGSIZE, TOTAL_MAX_ARGS, FULL_MAX_ARGS_ARR};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtRegsArm64 {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[map]
static EXEC_EVENTS: HashMap<u32, ExecsnoopEvent> = HashMap::with_max_entries(10240, 0);

#[map]
static EXEC_EVENTS_OUTPUT: PerfEventArray<ExecsnoopEvent> = PerfEventArray::new(0);

#[map]
static SCRATCH_BUF: PerCpuArray<ExecsnoopEvent> = PerCpuArray::with_max_entries(1, 0);

#[no_mangle]
static EXECSNOOP_TARG_UID: u32 = 0xFFFFFFFF; // INVALID_UID
#[no_mangle]
static EXECSNOOP_MAX_ARGS: u32 = 20; // DEFAULT_MAXARGS
#[no_mangle]
static EXECSNOOP_IGNORE_FAILED: u8 = 1;

#[kprobe]
pub fn execve_enter(ctx: ProbeContext) -> i32 {
    let regs_ptr = ctx.as_ptr() as *const PtRegsArm64;

    // Get the value of x0, which is the pointer to user regs
    let mut user_regs_ptr: *const PtRegsArm64 = core::ptr::null();
    unsafe {
        if let Ok(ptr) = bpf_probe_read_kernel(&(*regs_ptr).regs[0] as *const u64 as *const *const PtRegsArm64) {
            user_regs_ptr = ptr;
        }
    }

    if user_regs_ptr.is_null() {
        return 0;
    }

    let mut filename: *const u8 = core::ptr::null();
    let mut argv: *const *const u8 = core::ptr::null();

    unsafe {
        // Read real arguments from user_regs
        // regs[0] corresponds to x0 (filename)
        if let Ok(ptr) = bpf_probe_read_kernel(&(*user_regs_ptr).regs[0] as *const u64 as *const *const u8) {
            filename = ptr;
        }
        // regs[1] corresponds to x1 (argv)
        if let Ok(ptr) = bpf_probe_read_kernel(&(*user_regs_ptr).regs[1] as *const u64 as *const *const *const u8) {
            argv = ptr;
        }
    }

    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    let targ_uid = unsafe { core::ptr::read_volatile(&EXECSNOOP_TARG_UID) };
    let uid = bpf_get_current_uid_gid() as u32;

    if targ_uid != 0xFFFFFFFF && targ_uid != uid {
        return 0;
    }

    let event = unsafe {
        let ptr = match SCRATCH_BUF.get_ptr_mut(0) {
            Some(p) => p,
            None => return 0,
        };
        &mut *ptr
    };

    event.pid = tgid;
    event.ppid = 0;
    event.uid = uid;
    event.retval = 0;
    event.args_count = 0;
    event.args_size = 0;
    event.comm = [0; TASK_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // Read filename as the first argument
    let mut offset = 0;
    if !filename.is_null() {
        unsafe {
            let res = bpf_probe_read_user_str_bytes(
                filename,
                &mut event.args[offset..offset + ARGSIZE],
            );
            if let Ok(bytes) = res {
                let len = bytes.len();
                event.args_count += 1;
                event.args_size += len as u32;
                offset += len;
            }
        }
    }

    // Iterate through argv arguments
    let max_args = unsafe { core::ptr::read_volatile(&EXECSNOOP_MAX_ARGS) } as usize;
    if !argv.is_null() {
        for i in 1..TOTAL_MAX_ARGS {
            if i >= max_args {
                break;
            }

            unsafe {
                let res_ptr = bpf_probe_read_user(argv.add(i));
                if let Ok(arg_ptr) = res_ptr {
                    if arg_ptr.is_null() {
                        break;
                    }

                    if offset + ARGSIZE > FULL_MAX_ARGS_ARR {
                        break;
                    }

                    let res = bpf_probe_read_user_str_bytes(
                        arg_ptr,
                        &mut event.args[offset..offset + ARGSIZE],
                    );
                    if let Ok(bytes) = res {
                        let len = bytes.len();
                        event.args_count += 1;
                        event.args_size += len as u32;
                        offset += len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    let _ = EXEC_EVENTS.insert(&pid, event, 0);
    0
}

#[kretprobe]
pub fn execve_exit(ctx: RetProbeContext) -> i32 {
    // Directly read the return value via x0 register (offset 0) to avoid offset compatibility issues in aya-ebpf embedded bindings on aarch64
    let ret = unsafe {
        let regs = ctx.as_ptr() as *const i64;
        bpf_probe_read_kernel(regs).unwrap_or(-1) as i32
    };

    let ignore_failed = unsafe { core::ptr::read_volatile(&EXECSNOOP_IGNORE_FAILED) };
    if ignore_failed != 0 && ret < 0 {
        return 0;
    }

    let id = bpf_get_current_pid_tgid();
    let pid = id as u32;

    if let Some(event_ref) = unsafe { EXEC_EVENTS.get(&pid) } {
        let out_event = unsafe {
            let ptr = match SCRATCH_BUF.get_ptr_mut(0) {
                Some(p) => p,
                None => return 0,
            };
            &mut *ptr
        };

        *out_event = *event_ref;
        out_event.retval = ret;

        if let Ok(comm) = bpf_get_current_comm() {
            out_event.comm = comm;
        }

        EXEC_EVENTS_OUTPUT.output(&ctx, out_event, 0);
        let _ = EXEC_EVENTS.remove(&pid);
    }

    0
}
