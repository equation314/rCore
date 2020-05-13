//! VM exit handler

use bit_field::BitField;

use super::exit_reason::ExitReason;
use super::{vcpu::GuestState, vmcs::*};
use crate::rvm::{RvmError, RvmResult};

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
            exit_reason: full_reason.get_bits(0..16).into(),
            entry_failure: full_reason.get_bit(31),
            exit_instruction_length: vmcs.read32(VmcsField32::VM_EXIT_INSTRUCTION_LEN),
            exit_qualification: vmcs.readXX(VmcsFieldXX::EXIT_QUALIFICATION),
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

fn handle_external_interrupt(vmcs: &AutoVmcs) -> RvmResult<bool> {
    info!(
        "[RVM] External interrupt {:#x?}",
        vmcs.read32(VmcsField32::VM_EXIT_INTR_INFO)
    );
    // TODO: construct `TrapFrame` and call `arch::interrupt::handler::rust_trap()`
    Ok(false)
}

fn handle_vmcall(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
) -> RvmResult<bool> {
    exit_info.next_rip(vmcs);
    let num = guest_state.rax;
    let args = [
        guest_state.rbx,
        guest_state.rcx,
        guest_state.rdx,
        guest_state.rsi,
    ];
    guest_state.rax = 0;
    info!("[RVM] VMCALL({:#x}) args: {:x?}", num, args);
    Ok(false)
}

/// The common handler of VM exits.
///
/// Returns:
/// - `Ok(true)` if should forward it to the user mode handler.
/// - `Ok(false)` if the hypervisor has completed the exit handling and
///   can continue to run VMRESUME.
/// - `Err(RvmError)` if an error occurs.
pub fn vmexit_handler(vmcs: &mut AutoVmcs, guest_state: &mut GuestState) -> RvmResult<bool> {
    let exit_info = ExitInfo::new(vmcs);
    trace!(
        "[RVM] VM Exit: {:#x?} @ CPU{}",
        exit_info,
        crate::arch::cpu::id()
    );

    let res = match exit_info.exit_reason {
        ExitReason::EXTERNAL_INTERRUPT => handle_external_interrupt(vmcs),
        ExitReason::VMCALL => handle_vmcall(&exit_info, vmcs, guest_state),
        _ => Err(RvmError::NotSupported),
    };

    if res.is_err() {
        warn!(
            "[RVM] VM exit handler for reason {:?} returned {:?}\n{}",
            exit_info.exit_reason,
            res,
            guest_state.dump(&vmcs)
        );
    }
    res
}
