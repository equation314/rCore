//! VM exit handler

use alloc::sync::Arc;
use bit_field::BitField;
use spin::RwLock;

use super::exit_reason::ExitReason;
use super::guest_phys_memory_set::GuestPhysicalMemorySet;
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
    trace!(
        "[RVM] VM exit: External interrupt {:#x?}",
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
    println!("[RVM] VM exit: VMCALL({:#x}) args: {:x?}", num, args);
    Ok(false)
}

/// Check whether the EPT violation is caused by accessing MMIO region.
///
/// Returns:
/// - `Ok(true)` if it's an MMIO access, need to forward it to the userspace handler.
/// - `Ok(false)` if it's not an MMIO access, handle it as a normal EPT page fault.
/// - `Err(RvmError)` if an error occurs.
fn handle_mmio(
    _exit_info: &ExitInfo,
    _vmcs: &mut AutoVmcs,
    _guest_paddr: usize,
) -> RvmResult<bool> {
    // TODO
    Ok(false)
}

fn handle_ept_violation(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    gpm: &Arc<RwLock<GuestPhysicalMemorySet>>,
) -> RvmResult<bool> {
    let guest_paddr = vmcs.read64(VmcsField64::GUEST_PHYSICAL_ADDRESS) as usize;
    trace!(
        "[RVM] VM exit: EPT violation @ {:#x} RIP: {:#x}",
        guest_paddr,
        exit_info.guest_rip
    );

    let res = handle_mmio(exit_info, vmcs, guest_paddr);
    if res != Ok(false) {
        return res;
    }

    if !gpm.write().handle_page_fault(guest_paddr) {
        warn!("[RVM] Unhandled EPT violation @ {:#x}", guest_paddr);
        Err(RvmError::NoDeviceSpace)
    } else {
        Ok(false)
    }
}

/// The common handler of VM exits.
///
/// Returns:
/// - `Ok(true)` if need to forward it to the userspace handler.
/// - `Ok(false)` if the hypervisor has completed the exit handling and
///   can continue to run VMRESUME.
/// - `Err(RvmError)` if an error occurs.
pub fn vmexit_handler(
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
    gpm: &Arc<RwLock<GuestPhysicalMemorySet>>,
) -> RvmResult<bool> {
    let exit_info = ExitInfo::new(vmcs);
    trace!(
        "[RVM] VM exit: {:#x?} @ CPU{}",
        exit_info,
        crate::arch::cpu::id()
    );

    let res = match exit_info.exit_reason {
        ExitReason::EXTERNAL_INTERRUPT => handle_external_interrupt(vmcs),
        ExitReason::VMCALL => handle_vmcall(&exit_info, vmcs, guest_state),
        ExitReason::EPT_VIOLATION => handle_ept_violation(&exit_info, vmcs, gpm),
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
