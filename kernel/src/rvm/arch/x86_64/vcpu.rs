//! The virtual CPU within a guest.

use alloc::{boxed::Box, sync::Weak};
use x86_64::{
    instructions::vmx,
    registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags},
};

use super::{
    msr::*,
    structs::{MsrList, VmxPage},
    vmcs::*,
    Guest,
};
use crate::arch::{gdt, idt};
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
    _guest: Weak<Box<Guest>>,
    vmx_state: VmxState,
    vmcs_page: VmxPage,
    host_msr_list: MsrList,
    guest_msr_list: MsrList,
}

impl Vcpu {
    pub fn new(vpid: u16, guest: Weak<Box<Guest>>) -> RvmResult<Box<Self>> {
        // TODO pin thread

        let vmx_basic = VmxBasic::read();
        let host_msr_list = MsrList::new()?;
        let guest_msr_list = MsrList::new()?;
        let mut vmcs_page = VmxPage::alloc(0)?;
        vmcs_page.set_revision_id(vmx_basic.revision_id);

        Ok(Box::new(Self {
            vpid,
            _guest: guest,
            vmx_state: VmxState::default(),
            vmcs_page,
            host_msr_list,
            guest_msr_list,
        }))
    }

    pub fn resume(&mut self) {}

    pub fn init(&mut self, entry: u64) -> RvmResult<()> {
        unsafe {
            vmx::vmclear(self.vmcs_page.phys_addr()).ok_or(RvmError::DeviceError)?;
            let mut vmcs = AutoVmcs::new(self.vmcs_page.phys_addr())?;
            self.setup_msr_list();
            self.init_vmcs_host(&mut vmcs)?;
            self.init_vmcs_control(&mut vmcs)?;
            self.init_vmcs_guest(&mut vmcs, entry)?;
        }
        Ok(())
    }

    /// Setup MSRs to be stored and loaded on VM exits/entrie.
    unsafe fn setup_msr_list(&mut self) {
        let msr_list = [
            MSR_IA32_KERNEL_GS_BASE,
            MSR_IA32_STAR,
            MSR_IA32_LSTAR,
            MSR_IA32_FMASK,
            MSR_IA32_TSC_ADJUST,
            MSR_IA32_TSC_AUX,
        ];
        let count = msr_list.len();
        self.host_msr_list.set_count(count);
        self.guest_msr_list.set_count(count);
        for (i, &msr) in msr_list.iter().enumerate() {
            self.host_msr_list.edit_entry(i, msr, Msr::new(msr).read());
            self.guest_msr_list.edit_entry(i, msr, 0);
        }
    }

    /// Setup VMCS host state.
    unsafe fn init_vmcs_host(&self, vmcs: &mut AutoVmcs) -> RvmResult<()> {
        vmcs.write64(VmcsField64::HOST_IA32_PAT, Msr::new(MSR_IA32_EFER).read());
        vmcs.write64(VmcsField64::HOST_IA32_EFER, Msr::new(MSR_IA32_EFER).read());

        vmcs.writeXX(VmcsFieldXX::HOST_CR0, Cr0::read_raw() as usize);
        let cr3 = Cr3::read();
        vmcs.writeXX(
            VmcsFieldXX::HOST_CR3,
            (cr3.0.start_address().as_u64() | cr3.1.bits()) as usize,
        );
        vmcs.writeXX(VmcsFieldXX::HOST_CR4, Cr4::read_raw() as usize);

        vmcs.write16(VmcsField16::HOST_ES_SELECTOR, 0);
        vmcs.write16(VmcsField16::HOST_CS_SELECTOR, gdt::KCODE_SELECTOR.0);
        vmcs.write16(VmcsField16::HOST_SS_SELECTOR, gdt::KDATA_SELECTOR.0);
        vmcs.write16(VmcsField16::HOST_DS_SELECTOR, 0);
        vmcs.write16(VmcsField16::HOST_FS_SELECTOR, 0);
        vmcs.write16(VmcsField16::HOST_GS_SELECTOR, 0);
        vmcs.write16(VmcsField16::HOST_TR_SELECTOR, gdt::TSS_SELECTOR.0);

        vmcs.writeXX(
            VmcsFieldXX::HOST_FS_BASE,
            Msr::new(MSR_IA32_FS_BASE).read() as usize,
        );
        vmcs.writeXX(
            VmcsFieldXX::HOST_GS_BASE,
            Msr::new(MSR_IA32_GS_BASE).read() as usize,
        );
        vmcs.writeXX(VmcsFieldXX::HOST_TR_BASE, gdt::Cpu::current().tss_base());
        vmcs.writeXX(VmcsFieldXX::HOST_GDTR_BASE, gdt::sgdt().base as usize);
        vmcs.writeXX(VmcsFieldXX::HOST_IDTR_BASE, idt::sidt().base as usize);

        vmcs.writeXX(VmcsFieldXX::HOST_IA32_SYSENTER_ESP, 0);
        vmcs.writeXX(VmcsFieldXX::HOST_IA32_SYSENTER_EIP, 0);
        vmcs.write32(VmcsField32::HOST_IA32_SYSENTER_CS, 0);

        vmcs.writeXX(VmcsFieldXX::HOST_RSP, &self.vmx_state as *const _ as usize);
        vmcs.writeXX(VmcsFieldXX::HOST_RIP, 0); // TODO: vm exit entry
        Ok(())
    }

    /// Setup VMCS guest state.
    unsafe fn init_vmcs_guest(&self, vmcs: &mut AutoVmcs, _entry: u64) -> RvmResult<()> {
        vmcs.write64(VmcsField64::GUEST_IA32_PAT, Msr::new(MSR_IA32_PAT).read());
        vmcs.write64(VmcsField64::GUEST_IA32_EFER, Msr::new(MSR_IA32_EFER).read()); // TODO: Disable LME/LMA?

        vmcs.writeXX(VmcsFieldXX::GUEST_CR3, 0);
        let cr0 = Cr0Flags::NUMERIC_ERROR.bits() as usize;
        vmcs.writeXX(VmcsFieldXX::GUEST_CR0, cr0);
        // Ensure that CR0.NE remains set by masking and manually handling writes to CR0 that unset it.
        vmcs.writeXX(VmcsFieldXX::CR0_GUEST_HOST_MASK, cr0);
        vmcs.writeXX(VmcsFieldXX::CR0_READ_SHADOW, cr0);
        let cr4 = Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits() as usize;
        vmcs.writeXX(VmcsFieldXX::GUEST_CR4, cr4);
        // For now, the guest can own all of the CR4 bits except VMXE, which it shouldn't touch.
        vmcs.writeXX(VmcsFieldXX::CR4_GUEST_HOST_MASK, cr4);
        vmcs.writeXX(VmcsFieldXX::CR4_READ_SHADOW, 0);

        let default_rights = GuestRegisterAccessRights::default().bits();
        let cs_rights = default_rights | GuestRegisterAccessRights::EXECUTABLE.bits();

        // Setup CS and entry point. Use CS to set the entry point on APs.
        vmcs.write16(VmcsField16::GUEST_CS_SELECTOR, 0xf000);
        vmcs.writeXX(VmcsFieldXX::GUEST_CS_BASE, 0xffff_0000);
        vmcs.write32(VmcsField32::GUEST_CS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_CS_AR_BYTES, cs_rights);
        vmcs.writeXX(VmcsFieldXX::GUEST_RIP, 0x0000_fff0);

        // Setup DS, ES, FS, GS, TR, LDTR, GDTR, IDTR.
        vmcs.write16(VmcsField16::GUEST_DS_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_DS_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_DS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_DS_AR_BYTES, default_rights);
        vmcs.write16(VmcsField16::GUEST_ES_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_ES_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_ES_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_ES_AR_BYTES, default_rights);
        vmcs.write16(VmcsField16::GUEST_FS_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_FS_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_FS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_FS_AR_BYTES, default_rights);
        vmcs.write16(VmcsField16::GUEST_GS_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_GS_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_GS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_GS_AR_BYTES, default_rights);
        vmcs.write16(VmcsField16::GUEST_TR_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_TR_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_TR_LIMIT, 0xffff);
        vmcs.write32(
            VmcsField32::GUEST_TR_AR_BYTES,
            (GuestRegisterAccessRights::TSS_BUSY | GuestRegisterAccessRights::PRESENT).bits(),
        );
        vmcs.write16(VmcsField16::GUEST_LDTR_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_LDTR_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_LDTR_LIMIT, 0xffff);
        vmcs.write32(
            VmcsField32::GUEST_LDTR_AR_BYTES,
            (GuestRegisterAccessRights::WRITABLE | GuestRegisterAccessRights::PRESENT).bits(),
        );
        vmcs.writeXX(VmcsFieldXX::GUEST_GDTR_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_GDTR_LIMIT, 0xffff);
        vmcs.writeXX(VmcsFieldXX::GUEST_IDTR_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_IDTR_LIMIT, 0xffff);

        vmcs.writeXX(VmcsFieldXX::GUEST_RSP, 0);
        // Set all reserved RFLAGS bits to their correct values
        vmcs.writeXX(VmcsFieldXX::GUEST_RFLAGS, 0x2);

        vmcs.write32(VmcsField32::GUEST_INTERRUPTIBILITY_STATE, 0);
        vmcs.write32(VmcsField32::GUEST_ACTIVITY_STATE, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_PENDING_DBG_EXCEPTIONS, 0);

        // From Volume 3, Section 26.3.1.1: The IA32_SYSENTER_ESP field and the
        // IA32_SYSENTER_EIP field must each contain a canonical address.
        vmcs.writeXX(VmcsFieldXX::GUEST_IA32_SYSENTER_ESP, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_IA32_SYSENTER_EIP, 0);
        vmcs.write32(VmcsField32::GUEST_IA32_SYSENTER_CS, 0);

        // From Volume 3, Section 24.4.2: If the “VMCS shadowing” VM-execution
        // control is 1, the VMREAD and VMWRITE instructions access the VMCS
        // referenced by this pointer (see Section 24.10). Otherwise, software
        // should set this field to FFFFFFFF_FFFFFFFFH to avoid VM-entry
        // failures (see Section 26.3.1.5).
        vmcs.write64(VmcsField64::VMCS_LINK_POINTER, u64::MAX);

        Ok(())
    }

    /// Setup VMCS control fields.
    unsafe fn init_vmcs_control(&self, vmcs: &mut AutoVmcs) -> RvmResult<()> {
        use CpuBasedVmExecControls as CpuCtrl;
        use PinBasedVmExecControls as PinCtrl;
        use SecondaryCpuBasedVmExecControls as CpuCtrl2;

        // Setup secondary processor-based VMCS controls.
        vmcs.set_control(
            VmcsField32::SECONDARY_VM_EXEC_CONTROL,
            Msr::new(MSR_IA32_VMX_PROCBASED_CTLS2).read(),
            0,
            (CpuCtrl2::EPT
                | CpuCtrl2::RDTSCP
                | CpuCtrl2::VIRTUAL_X2APIC
                | CpuCtrl2::VPID
                | CpuCtrl2::UNRESTRICTED_GUEST)
                .bits(),
            0,
        )?;
        // Enable use of INVPCID instruction if available.
        vmcs.set_control(
            VmcsField32::SECONDARY_VM_EXEC_CONTROL,
            Msr::new(MSR_IA32_VMX_PROCBASED_CTLS2).read(),
            vmcs.read32(VmcsField32::SECONDARY_VM_EXEC_CONTROL) as u64,
            CpuCtrl2::INVPCID.bits(),
            0,
        )
        .ok();

        // Setup pin-based VMCS controls.
        vmcs.set_control(
            VmcsField32::PIN_BASED_VM_EXEC_CONTROL,
            Msr::new(MSR_IA32_VMX_TRUE_PINBASED_CTLS).read(),
            Msr::new(MSR_IA32_VMX_PINBASED_CTLS).read(),
            (PinCtrl::INTR_EXITING | PinCtrl::NMI_EXITING).bits(),
            0,
        )?;

        // Setup primary processor-based VMCS controls.
        vmcs.set_control(
            VmcsField32::CPU_BASED_VM_EXEC_CONTROL,
            Msr::new(MSR_IA32_VMX_TRUE_PROCBASED_CTLS).read(),
            Msr::new(MSR_IA32_VMX_PROCBASED_CTLS).read(),
            // Enable XXX
            (CpuCtrl::HLT_EXITING
                | CpuCtrl::VIRTUAL_TPR
                | CpuCtrl::UNCOND_IO_EXITING
                | CpuCtrl::USE_MSR_BITMAPS
                | CpuCtrl::PAUSE_EXITING
                | CpuCtrl::SEC_CONTROLS)
                .bits(),
            // Disable XXX
            (CpuCtrl::CR3_LOAD_EXITING
                | CpuCtrl::CR3_STORE_EXITING
                | CpuCtrl::CR8_LOAD_EXITING
                | CpuCtrl::CR8_STORE_EXITING)
                .bits(),
        )?;
        // TODO: InterruptWindowExiting?

        // Setup VM-exit VMCS controls.
        vmcs.set_control(
            VmcsField32::VM_EXIT_CONTROLS,
            Msr::new(MSR_IA32_VMX_TRUE_EXIT_CTLS).read(),
            Msr::new(MSR_IA32_VMX_EXIT_CTLS).read(),
            (VmExitControls::HOST_ADDR_SPACE_SIZE
                | VmExitControls::SAVE_IA32_PAT
                | VmExitControls::LOAD_IA32_PAT
                | VmExitControls::SAVE_IA32_EFER
                | VmExitControls::LOAD_IA32_EFER
                | VmExitControls::ACK_INTR_ON_EXIT)
                .bits(),
            0,
        )?;

        // Setup VM-entry VMCS controls.
        vmcs.set_control(
            VmcsField32::VM_ENTRY_CONTROLS,
            Msr::new(MSR_IA32_VMX_TRUE_ENTRY_CTLS).read(),
            Msr::new(MSR_IA32_VMX_ENTRY_CTLS).read(),
            (VmEntryControls::LOAD_IA32_PAT | VmEntryControls::LOAD_IA32_EFER).bits(),
            0,
        )?;

        // From Volume 3, Section 24.6.3: The exception bitmap is a 32-bit field
        // that contains one bit for each exception. When an exception occurs,
        // its vector is used to select a bit in this field. If the bit is 1,
        // the exception causes a VM exit. If the bit is 0, the exception is
        // delivered normally through the IDT, using the descriptor
        // corresponding to the exception’s vector.
        //
        // From Volume 3, Section 25.2: If software desires VM exits on all page
        // faults, it can set bit 14 in the exception bitmap to 1 and set the
        // page-fault error-code mask and match fields each to 00000000H.
        vmcs.write32(VmcsField32::EXCEPTION_BITMAP, 0);
        vmcs.write32(VmcsField32::PAGE_FAULT_ERROR_CODE_MASK, 0);
        vmcs.write32(VmcsField32::PAGE_FAULT_ERROR_CODE_MATCH, 0);

        // From Volume 3, Section 28.1: Virtual-processor identifiers (VPIDs)
        // introduce to VMX operation a facility by which a logical processor may
        // cache information for multiple linear-address spaces. When VPIDs are
        // used, VMX transitions may retain cached information and the logical
        // processor switches to a different linear-address space.
        //
        // From Volume 3, Section 26.2.1.1: If the “enable VPID” VM-execution
        // control is 1, the value of the VPID VM-execution control field must not
        // be 0000H.
        //
        // From Volume 3, Section 28.3.3.3: If EPT is in use, the logical processor
        // associates all mappings it creates with the value of bits 51:12 of
        // current EPTP. If a VMM uses different EPTP values for different guests,
        // it may use the same VPID for those guests.
        //
        // From Volume 3, Section 28.3.3.1: Operations that architecturally
        // invalidate entries in the TLBs or paging-structure caches independent of
        // VMX operation (e.g., the INVLPG and INVPCID instructions) invalidate
        // linear mappings and combined mappings. They are required to do so only
        // for the current VPID (but, for combined mappings, all EP4TAs). Linear
        // mappings for the current VPID are invalidated even if EPT is in use.
        // Combined mappings for the current VPID are invalidated even if EPT is
        // not in use.
        vmcs.write16(VmcsField16::VIRTUAL_PROCESSOR_ID, self.vpid);

        // From Volume 3, Section 28.2: The extended page-table mechanism (EPT) is a
        // feature that can be used to support the virtualization of physical
        // memory. When EPT is in use, certain addresses that would normally be
        // treated as physical addresses (and used to access memory) are instead
        // treated as guest-physical addresses. Guest-physical addresses are
        // translated by traversing a set of EPT paging structures to produce
        // physical addresses that are used to access memory.
        vmcs.write64(VmcsField64::EPT_POINTER, 0); // TODO: eptp

        // From Volume 3, Section 28.3.3.4: Software can use an INVEPT with type all
        // ALL_CONTEXT to prevent undesired retention of cached EPT information. Here,
        // we only care about invalidating information associated with this EPTP.
        vmx::invept(vmx::InvEptType::SingleContext, 0); // TODO: eptp

        // Setup MSR handling.
        vmcs.write64(VmcsField64::MSR_BITMAP, 0); // TODO: msr_bitmap_addr

        vmcs.write64(
            VmcsField64::VM_EXIT_MSR_LOAD_ADDR,
            self.host_msr_list.paddr(),
        );
        vmcs.write32(
            VmcsField32::VM_EXIT_MSR_LOAD_COUNT,
            self.host_msr_list.count(),
        );
        vmcs.write64(
            VmcsField64::VM_EXIT_MSR_STORE_ADDR,
            self.guest_msr_list.paddr(),
        );
        vmcs.write32(
            VmcsField32::VM_EXIT_MSR_STORE_COUNT,
            self.guest_msr_list.count(),
        );
        vmcs.write64(
            VmcsField64::VM_ENTRY_MSR_LOAD_ADDR,
            self.guest_msr_list.paddr(),
        );
        vmcs.write32(
            VmcsField32::VM_ENTRY_MSR_LOAD_COUNT,
            self.guest_msr_list.count(),
        );

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
