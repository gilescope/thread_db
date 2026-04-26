use crate::ffi::{ProcHandle, PsAddr};
use nix::libc;
use nix::unistd::Pid;
use nix::sys;
use std::ffi::{c_long, c_void, CStr};
use std::ptr;

#[cfg(target_arch = "x86_64")]
use nix::libc::user_regs_struct;
#[cfg(target_arch = "x86_64")]
use nix::errno::Errno::ESRCH;

/// Implementation of `/usr/include/proc_service.h`.
///
/// libthread_db.so dlopens its enclosing process and resolves these
/// `ps_*` symbols by name. They are the kernel-poking shims it uses to
/// reach the inferior. See:
/// http://timetobleed.com/notes-about-an-odd-esoteric-yet-incredibly-useful-library-libthread_db/

#[allow(unused)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub enum PsErr {
    /// Generic "call succeeded".
    Ok,
    /// Generic error.
    Err,
    /// Bad process handle.
    BadPID,
    /// Bad LWP identifier.
    BadLID,
    /// Bad address.
    BadAddr,
    /// Could not find given symbol.
    NoSym,
    /// FPU register set not available for given LWP.
    NoFRegs,
}

impl<T, E> From<Result<T, E>> for PsErr {
    fn from(r: Result<T, E>) -> Self {
        match r {
            Ok(_) => PsErr::Ok,
            Err(_) => PsErr::Err,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_getpid(handle: *mut ProcHandle) -> i32 {
    (*handle).pid.as_raw()
}

fn read(
    pid: Pid,
    mut source_ptr: *mut c_void,
    mut target_ptr: *mut c_void,
    mut size: usize,
) -> nix::Result<()> {
    let single_read_size = std::mem::size_of::<c_long>();
    loop {
        let data = sys::ptrace::read(pid, source_ptr)?;
        unsafe {
            if size > single_read_size {
                std::ptr::copy_nonoverlapping(
                    &data as *const _ as *const u8,
                    target_ptr as *mut u8,
                    single_read_size,
                );
            } else {
                std::ptr::copy_nonoverlapping(
                    &data as *const _ as *const u8,
                    target_ptr as *mut u8,
                    size,
                );
                break;
            }

            target_ptr = target_ptr.add(single_read_size);
            source_ptr = source_ptr.add(single_read_size);
            size -= single_read_size;
        }
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn ps_pdread(
    handle: *mut ProcHandle,
    ps_addr: *mut PsAddr,
    addr: *mut libc::c_void,
    size: usize,
) -> PsErr {
    read((*handle).pid, ps_addr, addr, size).into()
}

fn write(
    pid: Pid,
    mut target_ptr: *mut c_void,
    mut source_ptr: *mut c_void,
    mut size: usize,
) -> nix::Result<()> {
    let single_write_size = std::mem::size_of::<c_long>();
    unsafe {
        while size >= single_write_size {
            let word = ptr::read_unaligned(source_ptr as *mut c_long);
            sys::ptrace::write(pid, target_ptr, word as *mut c_void)?;

            target_ptr = target_ptr.add(single_write_size);
            source_ptr = source_ptr.add(single_write_size);
            size -= single_write_size;
        }

        if size > 0 {
            let mut data = sys::ptrace::read(pid, target_ptr)?;
            std::ptr::copy_nonoverlapping(
                source_ptr as *const u8,
                &mut data as *mut _ as *mut u8,
                size,
            );
            sys::ptrace::write(pid, target_ptr, data as *mut c_void)?
        }
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn ps_pdwrite(
    handle: *mut ProcHandle,
    ps_addr: *mut PsAddr,
    addr: *mut c_void,
    size: usize,
) -> PsErr {
    write((*handle).pid, ps_addr, addr, size).into()
}

// --- Register access -------------------------------------------------
//
// libthread_db needs to read/write a thread's general-purpose and
// floating-point register sets. The kernel API differs by arch:
//
//   x86_64:   PTRACE_GETREGS    / PTRACE_SETREGS    (struct user_regs_struct)
//             PTRACE_GETFPREGS  / PTRACE_SETFPREGS  (struct user_fpregs_struct)
//
//   aarch64:  PTRACE_GETREGSET(NT_PRSTATUS=1)  / SETREGSET (struct user_regs_struct)
//             PTRACE_GETREGSET(NT_FPREGSET=2)  / SETREGSET (struct user_fpsimd_struct)
//
// The shape of the buffer libthread_db passes us is whatever
// `prgregset_t` / `prfpregset_t` resolve to in the host's <sys/procfs.h>,
// which on glibc maps to `user_regs_struct` / `user_fpregs_struct`
// (x86_64) or `user_regs_struct` / `user_fpsimd_struct` (aarch64).

#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: libc::c_uint = 1;
#[cfg(target_arch = "aarch64")]
const NT_FPREGSET: libc::c_uint = 2;

#[cfg(target_arch = "aarch64")]
unsafe fn ptrace_regset(
    request: libc::c_uint,
    note_type: libc::c_uint,
    lwpid: libc::pid_t,
    buf: *mut libc::c_void,
    len: usize,
) -> PsErr {
    let mut iov = libc::iovec {
        iov_base: buf,
        iov_len: len,
    };
    let ret = libc::ptrace(
        request,
        lwpid,
        note_type as usize as *mut libc::c_void,
        &mut iov as *mut _ as *mut libc::c_void,
    );
    if ret < 0 {
        PsErr::Err
    } else {
        PsErr::Ok
    }
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lgetregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    match sys::ptrace::getregs(Pid::from_raw(lwpid)) {
        Ok(r) => {
            *(registers as *mut user_regs_struct) = r;
            PsErr::Ok
        }
        Err(_) => PsErr::Err,
    }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lgetregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    ptrace_regset(
        libc::PTRACE_GETREGSET,
        NT_PRSTATUS,
        lwpid,
        registers,
        std::mem::size_of::<libc::user_regs_struct>(),
    )
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lsetregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    let registers = registers as *mut user_regs_struct;
    sys::ptrace::setregs(Pid::from_raw(lwpid), *registers).into()
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lsetregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    ptrace_regset(
        libc::PTRACE_SETREGSET,
        NT_PRSTATUS,
        lwpid,
        registers,
        std::mem::size_of::<libc::user_regs_struct>(),
    )
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lgetfpregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    match libc::ptrace(libc::PTRACE_GETFPREGS, lwpid, 0, registers) {
        -1 => PsErr::Err,
        _ => PsErr::Ok,
    }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lgetfpregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    ptrace_regset(
        libc::PTRACE_GETREGSET,
        NT_FPREGSET,
        lwpid,
        registers,
        std::mem::size_of::<libc::user_fpsimd_struct>(),
    )
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lsetfpregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    match libc::ptrace(libc::PTRACE_SETFPREGS, lwpid, 0, registers) {
        -1 => PsErr::Err,
        _ => PsErr::Ok,
    }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn ps_lsetfpregs(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    registers: *mut libc::c_void,
) -> PsErr {
    ptrace_regset(
        libc::PTRACE_SETREGSET,
        NT_FPREGSET,
        lwpid,
        registers,
        std::mem::size_of::<libc::user_fpsimd_struct>(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn ps_pglobal_lookup(
    handle: *mut ProcHandle,
    object_name: *const libc::c_char,
    sym_name: *const libc::c_char,
    sym_addr: *mut *mut PsAddr,
) -> PsErr {
    let _object_name = CStr::from_ptr(object_name).to_str().unwrap();
    let sym_name = CStr::from_ptr(sym_name).to_str().unwrap();

    let symbols = &(*handle).symbols;

    let mb_addr = symbols
        .iter()
        .find_map(|(_, obj_symbols)| obj_symbols.get(sym_name));

    if let Some(addr) = mb_addr {
        *sym_addr = *addr as *mut PsAddr;
        return PsErr::Ok;
    }
    PsErr::NoSym
}

/// Fetch the special per-thread address associated with the given LWP.
/// This call is only used on platforms with segment-based TLS (x86 fs/gs);
/// on aarch64 glibc reads `TPIDR_EL0` directly via the regset interface
/// and never asks us, but the symbol must still resolve at dlopen time
/// — provide a `NoFRegs` stub so libthread_db falls back to the
/// ABI-default path if it ever does call this.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ps_get_thread_area(
    _handle: *mut ProcHandle,
    lwpid: libc::pid_t,
    idx: i32,
    addr: *mut *mut PsAddr,
) -> PsErr {
    let target_reg = match idx {
        libc::FS => |regs: user_regs_struct| regs.fs_base,
        libc::GS => |regs: user_regs_struct| regs.gs_base,
        _ => return PsErr::NoFRegs,
    };

    match sys::ptrace::getregs(Pid::from_raw(lwpid)) {
        Ok(regs) => {
            let reg_val = target_reg(regs) as usize;
            *addr = reg_val as *mut PsAddr;
            PsErr::Ok
        }
        Err(ESRCH) => PsErr::BadLID,
        Err(_) => PsErr::Err,
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn ps_get_thread_area(
    _handle: *mut ProcHandle,
    _lwpid: libc::pid_t,
    _idx: i32,
    _addr: *mut *mut PsAddr,
) -> PsErr {
    PsErr::NoFRegs
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::c_void;
    use nix::sys::signal::{raise, Signal};
    use nix::sys::wait::{WaitPidFlag, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use std::mem::size_of;

    #[test]
    fn test_pdread() {
        let mut u64_value = 0x1122334455667788u64;
        let mut u32_value = 0x11223344;
        let uarr: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut string_value = "abcdefghijklmnopqrstuvwxyz123456879".to_string();

        match unsafe { fork().unwrap() } {
            ForkResult::Child => {
                sys::ptrace::traceme().unwrap();
                raise(Signal::SIGSTOP).unwrap();
                std::thread::sleep(std::time::Duration::from_secs(2));
                std::process::exit(0);
            }
            ForkResult::Parent { child } => {
                sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

                unsafe {
                    let mut handle = ProcHandle::new(child).unwrap();
                    let mut result: u64 = 0;
                    assert_eq!(
                        ps_pdread(
                            &mut handle,
                            &mut u64_value as *mut _ as *mut c_void,
                            &mut result as *mut _ as *mut c_void,
                            size_of::<u64>()
                        ),
                        PsErr::Ok
                    );
                    assert_eq!(result, 0x1122334455667788u64);

                    result = 0;
                    assert_eq!(
                        ps_pdread(
                            &mut handle,
                            &mut u32_value as *mut _ as *mut c_void,
                            &mut result as *mut _ as *mut c_void,
                            size_of::<u32>()
                        ),
                        PsErr::Ok
                    );
                    assert_eq!(result, 0x11223344);

                    let mut result = vec![0u8; string_value.len()];
                    assert_eq!(
                        ps_pdread(
                            &mut handle,
                            string_value.as_bytes_mut() as *mut _ as *mut c_void,
                            result.as_mut_slice().as_mut_ptr() as *mut c_void,
                            string_value.len()
                        ),
                        PsErr::Ok
                    );
                    assert_eq!(
                        String::from_utf8_lossy(&result),
                        "abcdefghijklmnopqrstuvwxyz123456879"
                    );

                    let mut result = vec![0u8; 12];
                    assert_eq!(
                        ps_pdread(
                            &mut handle,
                            uarr.as_ptr() as *mut u8 as *mut c_void,
                            result.as_mut_slice().as_mut_ptr() as *mut c_void,
                            12
                        ),
                        PsErr::Ok
                    );
                    assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
                }

                sys::ptrace::cont(child, None).unwrap();
                let status = sys::wait::waitpid(child, None).unwrap();
                assert!(matches!(status, WaitStatus::Exited(_, 0)));
            }
        }
    }

    #[test]
    fn test_pdwrite() {
        let str_val = "abcdefghijklmnopqrstuvwxyz123456879";
        let mut u64_var = 0;
        let mut u32_var = 0;
        let mut str_var = vec![0u8; str_val.len()];
        let str_ptr = str_var.as_mut_slice().as_mut_ptr();

        match unsafe { fork().unwrap() } {
            ForkResult::Child => {
                sys::ptrace::traceme().unwrap();
                raise(Signal::SIGSTOP).unwrap();
                std::thread::sleep(std::time::Duration::from_secs(1));
                if u64_var != 0x1122334455667788u64 {
                    std::process::exit(1)
                };
                if u32_var != 0x11223344 {
                    std::process::exit(1)
                };
                if String::from_utf8_lossy(&str_var) != str_val {
                    std::process::exit(1)
                };
                std::process::exit(0)
            }
            ForkResult::Parent { child } => {
                let mut handle = ProcHandle::new(child).unwrap();

                sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

                let mut u64_value = 0x1122334455667788u64;
                let mut u32_value = 0x11223344;
                unsafe {
                    assert_eq!(
                        ps_pdwrite(
                            &mut handle,
                            &mut u64_var as *mut _ as *mut c_void,
                            &mut u64_value as *mut _ as *mut c_void,
                            size_of::<u64>(),
                        ),
                        PsErr::Ok
                    );
                    assert_eq!(
                        ps_pdwrite(
                            &mut handle,
                            &mut u32_var as *mut _ as *mut c_void,
                            &mut u32_value as *mut _ as *mut c_void,
                            size_of::<u32>(),
                        ),
                        PsErr::Ok
                    );
                    assert_eq!(
                        ps_pdwrite(
                            &mut handle,
                            str_ptr as *mut c_void,
                            str_val.as_ptr() as *mut c_void,
                            str_val.len(),
                        ),
                        PsErr::Ok
                    );
                }

                sys::ptrace::cont(child, None).unwrap();

                let status = sys::wait::waitpid(child, None).unwrap();
                assert!(matches!(status, WaitStatus::Exited(_, 0)));
            }
        }
    }
}
