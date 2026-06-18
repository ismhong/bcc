#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const PATH_MAX: usize = 256;
pub const ARGSIZE: usize = 128;
pub const TOTAL_MAX_ARGS: usize = 60;
pub const FULL_MAX_ARGS_ARR: usize = TOTAL_MAX_ARGS * ARGSIZE;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpensnoopEvent {
    pub ts: u64,
    pub pid: u32,
    pub uid: u32,
    pub ret: i32,
    pub flags: i32,
    pub mode: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub fname: [u8; PATH_MAX],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecsnoopEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub retval: i32,
    pub args_count: i32,
    pub args_size: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub args: [u8; FULL_MAX_ARGS_ARR],
}

pub const MAX_SLOTS: usize = 20;
pub const NR_SOFTIRQS: usize = 10;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Hist {
    pub slots: [u32; MAX_SLOTS],
}

