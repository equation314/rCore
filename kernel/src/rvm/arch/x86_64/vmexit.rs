//! VM exit handler

use bit_field::BitField;

use super::{vcpu::GuestState, vmcs::*};
use crate::rvm::{RvmError, RvmResult};

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum ExitReason {
    EXCEPTION_OR_NMI = 0,
    EXTERNAL_INTERRUPT = 1,
    TRIPLE_FAULT = 2,
    INIT_SIGNAL = 3,
    STARTUP_IPI = 4,
    IO_SMI = 5,
    OTHER_SMI = 6,
    INTERRUPT_WINDOW = 7,
    NMI_WINDOW = 8,
    TASK_SWITCH = 9,
    CPUID = 10,
    GETSEC = 11,
    HLT = 12,
    INVD = 13,
    INVLPG = 14,
    RDPMC = 15,
    RDTSC = 16,
    RSM = 17,
    VMCALL = 18,
    VMCLEAR = 19,
    VMLAUNCH = 20,
    VMPTRLD = 21,
    VMPTRST = 22,
    VMREAD = 23,
    VMRESUME = 24,
    VMWRITE = 25,
    VMXOFF = 26,
    VMXON = 27,
    CONTROL_REGISTER_ACCESS = 28,
    MOV_DR = 29,
    IO_INSTRUCTION = 30,
    RDMSR = 31,
    WRMSR = 32,
    ENTRY_FAILURE_GUEST_STATE = 33,
    ENTRY_FAILURE_MSR_LOADING = 34,
    MWAIT = 36,
    MONITOR_TRAP_FLAG = 37,
    MONITOR = 39,
    PAUSE = 40,
    ENTRY_FAILURE_MACHINE_CHECK = 41,
    TPR_BELOW_THRESHOLD = 43,
    APIC_ACCESS = 44,
    VIRTUALIZED_EOI = 45,
    ACCESS_GDTR_OR_IDTR = 46,
    ACCESS_LDTR_OR_TR = 47,
    EPT_VIOLATION = 48,
    EPT_MISCONFIGURATION = 49,
    INVEPT = 50,
    RDTSCP = 51,
    VMX_PREEMPT_TIMER_EXPIRED = 52,
    INVVPID = 53,
    WBINVD = 54,
    XSETBV = 55,
    APIC_WRITE = 56,
    RDRAND = 57,
    INVPCID = 58,
    VMFUNC = 59,
    ENCLS = 60,
    RDSEED = 61,
    PAGE_MODIFICATION_LOG_FULL = 62,
    XSAVES = 63,
    XRSTORS = 64,
    SPP_EVENT = 66,
    UMWAIT = 67,
    TPAUSE = 68,
}

#[derive(Debug)]
struct ExitInfo {
    entry_failure: bool,
    exit_reason: ExitReason,
    exit_instruction_length: u32,
    exit_qualification: usize,
    guest_rip: usize,
}

impl ExitInfo {
    fn new(vmcs: &AutoVmcs) -> Self {
        let full_reason = vmcs.read32(VmcsField32::VM_EXIT_REASON);
        Self {
            exit_reason: unsafe { core::mem::transmute(full_reason.get_bits(0..16)) },
            entry_failure: full_reason.get_bit(31),
            exit_qualification: vmcs.readXX(VmcsFieldXX::EXIT_QUALIFICATION),
            exit_instruction_length: vmcs.read32(VmcsField32::VM_EXIT_INSTRUCTION_LEN),
            guest_rip: vmcs.readXX(VmcsFieldXX::GUEST_RIP),
        }
    }

    fn next_rip(&self, vmcs: &mut AutoVmcs) {
        vmcs.writeXX(
            VmcsFieldXX::GUEST_RIP,
            self.guest_rip + self.exit_instruction_length as usize,
        )
    }
}

/// The common handler of VM exits.
///
/// Returns:
/// - `Ok(true)` if should forward it to the user mode handler.
/// - `Ok(false)` if the hypervisor has completed the exit handling and
///   can continue to run VMRESUME.
/// - `Err(RvmError)` if an error occurs.
pub fn vmexit_handler(vmcs: &mut AutoVmcs, guest_state: &GuestState) -> RvmResult<bool> {
    let exit_info = ExitInfo::new(vmcs);
    println!("VM Exit: {:#x?} @ CPU{}", exit_info, crate::arch::cpu::id());

    let res = match exit_info.exit_reason {
        _ => Err(RvmError::NotSupported),
    };

    if res.is_err() {
        warn!(
            "[RVM]: VM exit handler for {:?} at RIP {:#x} returned {:?}",
            exit_info.exit_reason, exit_info.guest_rip, res
        );
    }
    res
}
