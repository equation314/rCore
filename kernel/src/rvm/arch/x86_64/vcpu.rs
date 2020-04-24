//! The virtual CPU within a guest.

use alloc::sync::Weak;
use spin::RwLock;
use x86_64::instructions::vmx;

use super::{msr::*, vmcs::*, vmm::VmxPage, Guest};
use crate::rvm::{RvmError, RvmResult};

/// Holds the register state used to restore a host.
#[repr(C)]
#[derive(Debug, Default)]
struct HostState {
    // Return address.
    rip: u64,

    // Callee-save registers.
    rbx: u64,
    rsp: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,

    // Processor flags.
    rflags: u64,

    // Extended control registers.
    xcr0: u64,
}

/// Holds the register state used to restore a guest.
#[repr(C)]
#[derive(Debug, Default)]
struct GuestState {
    //  RIP, RSP, and RFLAGS are automatically saved by VMX in the VMCS.
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,

    // Control registers.
    cr2: u64,

    // Extended control registers.
    xcr0: u64,
}

/// Host and guest cpu register states.
#[derive(Debug, Default)]
struct VmxState {
    resume: bool,
    host_state: HostState,
    guest_state: GuestState,
}

/// Represents a virtual CPU within a guest.
#[derive(Debug)]
pub struct Vcpu {
    vpid: u16,
    _guest: Weak<RwLock<Guest>>,
    vmx_state: VmxState,
    vmcs_page: VmxPage,
    host_msr_page: VmxPage,
    guest_msr_page: VmxPage,
}

impl Vcpu {
    pub fn new(guest: Weak<RwLock<Guest>>, vpid: u16, entry: u64) -> RvmResult<Self> {
        println!("{:#x} {:#x}", vpid, entry);

        // TODO pin thread

        let vmx_basic = VmxBasic::read();
        let host_msr_page = VmxPage::alloc(0)?;
        let guest_msr_page = VmxPage::alloc(0)?;
        let mut vmcs_page = VmxPage::alloc(0)?;
        vmcs_page.set_revision_id(vmx_basic.revision_id);

        let mut vcpu = Self {
            vpid,
            _guest: guest,
            vmx_state: VmxState::default(),
            vmcs_page,
            host_msr_page,
            guest_msr_page,
        };
        vcpu.init_vmcs(entry)?;
        println!("{:#x?}", vcpu);
        Ok(vcpu)
    }

    pub fn resume(&mut self) {}

    fn init_vmcs(&mut self, entry: u64) -> RvmResult<()> {
        unsafe { vmx::vmclear(self.vmcs_page.phys_addr()).ok_or(RvmError::DeviceError)? };
        let vmcs = AutoVmcs::new(self.vmcs_page.phys_addr())?;
        Ok(())
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        println!("Vcpu free {:#x?}", self);
        // TODO pin thread
        unsafe { vmx::vmclear(self.vmcs_page.phys_addr()) };
    }
}
