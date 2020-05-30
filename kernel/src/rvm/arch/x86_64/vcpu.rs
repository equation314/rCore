//! The virtual CPU within a guest.

use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::{
    instructions::vmx,
    registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags},
    registers::model_specific::{Efer, EferFlags},
};

use super::{
    msr::*,
    structs::{MsrList, VmxPage},
    vmcs::*,
    vmexit::vmexit_handler,
    Guest,
};
use crate::arch::{gdt, idt};
use crate::rvm::trap_map::TrapKind;
use crate::rvm::{
    packet::{IoPacket, IoValue, RvmExitPacket},
    RvmError, RvmResult,
};

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
pub struct GuestState {
    //  RIP, RSP, and RFLAGS are automatically saved by VMX in the VMCS.
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Control registers.
    pub cr2: u64,

    // Extended control registers.
    pub xcr0: u64,
}

impl GuestState {
    pub fn dump(&self, vmcs: &AutoVmcs) -> alloc::string::String {
        format!(
            "VCPU Dump:\n\
            RIP: {:#x?}\n\
            RSP: {:#x?}\n\
            RFLAGS: {:#x?}\n\
            CR0: {:#x?}\n\
            CR3: {:#x?}\n\
            CR4: {:#x?}\n\
            {:#x?}",
            vmcs.readXX(VmcsFieldXX::GUEST_RIP),
            vmcs.readXX(VmcsFieldXX::GUEST_RSP),
            vmcs.readXX(VmcsFieldXX::GUEST_RFLAGS),
            Cr0Flags::from_bits_truncate(vmcs.readXX(VmcsFieldXX::GUEST_CR0) as u64),
            vmcs.readXX(VmcsFieldXX::GUEST_CR3),
            Cr4Flags::from_bits_truncate(vmcs.readXX(VmcsFieldXX::GUEST_CR4) as u64),
            self
        )
    }
}

/// Host and guest cpu register states.
#[repr(C)]
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
    guest: Arc<Box<Guest>>,
    running: AtomicBool,
    vmx_state: VmxState,
    vmcs_page: VmxPage,
    host_msr_list: MsrList,
    guest_msr_list: MsrList,
    repeating: Repeating,
}

/// Represents a repeat operation
#[derive(Debug, Clone, Copy)]
pub enum Repeating {
    None,
    InOut(RepeatingInOut),
}

#[derive(Debug, Clone, Copy)]
pub struct RepeatingInOut {
    pub port: u16,
    pub access_size: u8,
    pub input: bool,

    pub guest_paddr: usize,
}

impl Vcpu {
    pub fn new(vpid: u16, guest: Arc<Box<Guest>>) -> RvmResult<Box<Self>> {
        // TODO pin thread

        let vmx_basic = VmxBasic::read();
        let host_msr_list = MsrList::new()?;
        let guest_msr_list = MsrList::new()?;
        let mut vmcs_page = VmxPage::alloc(0)?;
        vmcs_page.set_revision_id(vmx_basic.revision_id);

        Ok(Box::new(Self {
            vpid,
            guest,
            running: AtomicBool::new(false),
            vmx_state: VmxState::default(),
            vmcs_page,
            host_msr_list,
            guest_msr_list,
            repeating: Repeating::None,
        }))
    }

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
        vmcs.write64(VmcsField64::HOST_IA32_PAT, Msr::new(MSR_IA32_PAT).read());
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
        vmcs.writeXX(VmcsFieldXX::HOST_RIP, vmx_exit as usize);
        Ok(())
    }

    /// Setup VMCS guest state.
    unsafe fn init_vmcs_guest(&self, vmcs: &mut AutoVmcs, entry: u64) -> RvmResult<()> {
        vmcs.write64(VmcsField64::GUEST_IA32_PAT, Msr::new(MSR_IA32_PAT).read());
        let mut efer = Efer::read();
        efer.remove(EferFlags::LONG_MODE_ENABLE | EferFlags::LONG_MODE_ACTIVE);
        vmcs.write64(VmcsField64::GUEST_IA32_EFER, efer.bits());

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

        // Setup CS and entry point.
        vmcs.write32(VmcsField32::GUEST_CS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_CS_AR_BYTES, cs_rights);
        if entry > 0 {
            vmcs.write16(VmcsField16::GUEST_CS_SELECTOR, 0);
            vmcs.writeXX(VmcsFieldXX::GUEST_CS_BASE, 0);
            vmcs.writeXX(VmcsFieldXX::GUEST_RIP, entry as usize);
        } else {
            // Reference: Volume 3, Section 9.1.4, First Instruction Executed.
            vmcs.write16(VmcsField16::GUEST_CS_SELECTOR, 0xf000);
            vmcs.writeXX(VmcsFieldXX::GUEST_CS_BASE, 0xffff_0000);
            vmcs.writeXX(VmcsFieldXX::GUEST_RIP, 0xfff0);
        }

        // Setup DS, SS, ES, FS, GS, TR, LDTR, GDTR, IDTR.
        vmcs.write16(VmcsField16::GUEST_DS_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_DS_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_DS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_DS_AR_BYTES, default_rights);
        vmcs.write16(VmcsField16::GUEST_SS_SELECTOR, 0);
        vmcs.writeXX(VmcsFieldXX::GUEST_SS_BASE, 0);
        vmcs.write32(VmcsField32::GUEST_SS_LIMIT, 0xffff);
        vmcs.write32(VmcsField32::GUEST_SS_AR_BYTES, default_rights);
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
        let eptp = self.guest.eptp() as u64;
        vmcs.write64(VmcsField64::EPT_POINTER, eptp);

        // From Volume 3, Section 28.3.3.4: Software can use an INVEPT with type all
        // ALL_CONTEXT to prevent undesired retention of cached EPT information. Here,
        // we only care about invalidating information associated with this EPTP.
        vmx::invept(vmx::InvEptType::SingleContext, eptp);

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

    pub fn resume(&mut self) -> RvmResult<RvmExitPacket> {
        loop {
            let mut vmcs = AutoVmcs::new(self.vmcs_page.phys_addr())?;

            if let Repeating::InOut(op) = self.repeating {
                let ecx = self.vmx_state.guest_state.rcx & 0xFFFFFFFF;
                if ecx == 0 {
                    self.repeating = Repeating::None;
                    info!("[RVM] repeating end");
                } else {
                    let value = if op.input {
                        IoValue::default()
                    } else {
                        let data = self
                            .guest
                            .gpm
                            .write()
                            .fetch_data(op.guest_paddr, op.access_size as usize);
                        IoValue::from_raw_parts(data.as_ptr(), op.access_size)
                    };
                    let trap = match self.guest.traps.read().find(TrapKind::Io, op.port as usize) {
                        Some(t) => t,
                        None => panic!("[RVM] Error in repeat operation: can not find trap"),
                    };
                    return Ok(RvmExitPacket::new_io_packet(
                        trap.key,
                        IoPacket {
                            port: op.port,
                            access_size: op.access_size,
                            input: op.input,
                            value,
                        },
                    ));
                }
            }

            // TODO: interrupt virtualization
            // TODO: save/restore guest extended registers (x87/SSE)

            // VM Entry
            self.running.store(true, Ordering::SeqCst);
            let res = unsafe { vmx_entry(&mut self.vmx_state) };
            self.running.store(false, Ordering::SeqCst);

            res.map_err(|err| {
                warn!(
                    "[RVM] VCPU resume failed: {:#x}",
                    vmcs.read32(VmcsField32::VM_INSTRUCTION_ERROR)
                );
                err
            })?;

            // VM Exit
            self.vmx_state.resume = true;
            let mut out_repeating = Repeating::None;
            match vmexit_handler(
                &mut vmcs,
                &mut self.vmx_state.guest_state,
                &self.guest.gpm,
                &self.guest.traps,
                &mut out_repeating,
            )? {
                Some(packet) => return Ok(packet), // forward to user mode handler
                None => {
                    if let Repeating::InOut(x) = out_repeating {
                        info!("[RVM] Repeating: {:?}", x);
                        self.repeating = out_repeating;
                    }
                    continue;
                }
            }
        }
    }

    pub fn write_input_value(&mut self, access_size: u8, value: IoValue) -> RvmResult<()> {
        if let Repeating::InOut(op) = self.repeating {
            assert_eq!(access_size, op.access_size);

            info!("[RVM] write repeat input value, access_size = {}, value = 0x{:x}, guest_paddr = 0x{:x}", access_size, unsafe { value.d_u32 }, op.guest_paddr);
            self.guest.gpm.write().write_data(op.guest_paddr, unsafe {
                &value.buf[..(access_size as usize)]
            });
            // FIXME: may need invalidate guest cache

            let mut ecx = self.vmx_state.guest_state.rcx & 0xFFFFFFFF;
            ecx -= 1;
            self.vmx_state.guest_state.rcx = ecx;

            let mut op = op;
            op.guest_paddr += access_size as usize;
            self.repeating = Repeating::InOut(op);
        } else {
            self.vmx_state.guest_state.rax = unsafe { value.d_u32 as u64 };
        }
        Ok(())
    }

    pub fn write_state(&mut self, rax: u64) -> RvmResult<()> {
        // TODO: write other states
        self.vmx_state.guest_state.rax = rax;
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

#[naked]
#[inline(never)]
unsafe fn vmx_entry(_vmx_state: &mut VmxState) -> RvmResult<()> {
    let host_off = offset_of!(VmxState, host_state);
    let guest_off = offset_of!(VmxState, guest_state);
    asm!("
    // Store host callee save registers, return address, and processor flags.
    pop     qword ptr [rdi + $0] // rip
    mov     [rdi + $1], rbx
    mov     [rdi + $2], rsp
    mov     [rdi + $3], rbp
    mov     [rdi + $4], r12
    mov     [rdi + $5], r13
    mov     [rdi + $6], r14
    mov     [rdi + $7], r15
    pushf
    pop     qword ptr [rdi + $8] // rflags

    // We are going to trample RDI, so move it to RSP.
    mov     rsp, rdi

    // Load the guest registers not covered by the VMCS.
    mov     rax, [rsp + $9]
    mov     cr2, rax
    mov     rax, [rsp + $10]
    mov     rcx, [rsp + $11]
    mov     rdx, [rsp + $12]
    mov     rbx, [rsp + $13]
    mov     rbp, [rsp + $14]
    mov     rsi, [rsp + $15]
    mov     rdi, [rsp + $16]
    mov     r8, [rsp + $17]
    mov     r9, [rsp + $18]
    mov     r10, [rsp + $19]
    mov     r11, [rsp + $20]
    mov     r12, [rsp + $21]
    mov     r13, [rsp + $22]
    mov     r14, [rsp + $23]
    mov     r15, [rsp + $24]

    // Check if vmlaunch or vmresume is needed
    cmp     byte ptr [rsp + $25], 0
    jne     1f
    vmlaunch
    jmp     2f
1:  vmresume
2:
    // We will only be here if vmlaunch or vmresume failed.
    // Restore host callee, RSP and return address.
    mov     rdi, rsp
    mov     rbx, [rdi + $1]
    mov     rsp, [rdi + $2]
    mov     rbp, [rdi + $3]
    mov     r12, [rdi + $4]
    mov     r13, [rdi + $5]
    mov     r14, [rdi + $6]
    mov     r15, [rdi + $7]
    push    qword ptr [rdi + $8] // rflags
    popf
    push    qword ptr [rdi + $0] // rip
"
    :
    : "i" (host_off + offset_of!(HostState, rip)),
      "i" (host_off + offset_of!(HostState, rbx)),
      "i" (host_off + offset_of!(HostState, rsp)),
      "i" (host_off + offset_of!(HostState, rbp)),
      "i" (host_off + offset_of!(HostState, r12)),
      "i" (host_off + offset_of!(HostState, r13)),
      "i" (host_off + offset_of!(HostState, r14)),
      "i" (host_off + offset_of!(HostState, r15)),
      "i" (host_off + offset_of!(HostState, rflags)),

      "i" (guest_off + offset_of!(GuestState, cr2)),
      "i" (guest_off + offset_of!(GuestState, rax)),
      "i" (guest_off + offset_of!(GuestState, rcx)),
      "i" (guest_off + offset_of!(GuestState, rdx)),
      "i" (guest_off + offset_of!(GuestState, rbx)),
      "i" (guest_off + offset_of!(GuestState, rbp)),
      "i" (guest_off + offset_of!(GuestState, rsi)),
      "i" (guest_off + offset_of!(GuestState, rdi)),
      "i" (guest_off + offset_of!(GuestState, r8)),
      "i" (guest_off + offset_of!(GuestState, r9)),
      "i" (guest_off + offset_of!(GuestState, r10)),
      "i" (guest_off + offset_of!(GuestState, r11)),
      "i" (guest_off + offset_of!(GuestState, r12)),
      "i" (guest_off + offset_of!(GuestState, r13)),
      "i" (guest_off + offset_of!(GuestState, r14)),
      "i" (guest_off + offset_of!(GuestState, r15)),

      "i" (offset_of!(VmxState, resume))
    : "cc", "memory",
      "rax", "rbx", "rcx", "rdx", "rdi", "rsi"
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    : "intel", "volatile");

    // We will only be here if vmlaunch or vmresume failed.
    Err(RvmError::DeviceError)
}

/// This is effectively the second-half of vmx_entry. When we return from a
/// VM exit, vmx_state argument is stored in RSP. We use this to restore the
/// stack and registers to the state they were in when vmx_entry was called.
#[naked]
#[inline(never)]
unsafe fn vmx_exit(_vmx_state: &mut VmxState) -> RvmResult<()> {
    let host_off = offset_of!(VmxState, host_state);
    let guest_off = offset_of!(VmxState, guest_state);
    asm!("
    // Store the guest registers not covered by the VMCS. At this point,
    // vmx_state is in RSP.
    mov     [rsp + $10], rax
    mov     [rsp + $11], rcx
    mov     [rsp + $12], rdx
    mov     [rsp + $13], rbx
    mov     [rsp + $14], rbp
    mov     [rsp + $15], rsi
    mov     [rsp + $16], rdi
    mov     [rsp + $17], r8
    mov     [rsp + $18], r9
    mov     [rsp + $19], r10
    mov     [rsp + $20], r11
    mov     [rsp + $21], r12
    mov     [rsp + $22], r13
    mov     [rsp + $23], r14
    mov     [rsp + $24], r15
    mov     rax, cr2
    mov     [rsp + $9], rax

    // Load vmx_state from RSP into RDI.
    mov     rdi, rsp

    // Load host callee save registers, return address, and processor flags.
    mov     rbx, [rdi + $1]
    mov     rsp, [rdi + $2]
    mov     rbp, [rdi + $3]
    mov     r12, [rdi + $4]
    mov     r13, [rdi + $5]
    mov     r14, [rdi + $6]
    mov     r15, [rdi + $7]
    push    qword ptr [rdi + $8] // rflags
    popf
    push    qword ptr [rdi + $0] // rip
"
    :
    : "i" (host_off + offset_of!(HostState, rip)),
      "i" (host_off + offset_of!(HostState, rbx)),
      "i" (host_off + offset_of!(HostState, rsp)),
      "i" (host_off + offset_of!(HostState, rbp)),
      "i" (host_off + offset_of!(HostState, r12)),
      "i" (host_off + offset_of!(HostState, r13)),
      "i" (host_off + offset_of!(HostState, r14)),
      "i" (host_off + offset_of!(HostState, r15)),
      "i" (host_off + offset_of!(HostState, rflags)),

      "i" (guest_off + offset_of!(GuestState, cr2)),
      "i" (guest_off + offset_of!(GuestState, rax)),
      "i" (guest_off + offset_of!(GuestState, rcx)),
      "i" (guest_off + offset_of!(GuestState, rdx)),
      "i" (guest_off + offset_of!(GuestState, rbx)),
      "i" (guest_off + offset_of!(GuestState, rbp)),
      "i" (guest_off + offset_of!(GuestState, rsi)),
      "i" (guest_off + offset_of!(GuestState, rdi)),
      "i" (guest_off + offset_of!(GuestState, r8)),
      "i" (guest_off + offset_of!(GuestState, r9)),
      "i" (guest_off + offset_of!(GuestState, r10)),
      "i" (guest_off + offset_of!(GuestState, r11)),
      "i" (guest_off + offset_of!(GuestState, r12)),
      "i" (guest_off + offset_of!(GuestState, r13)),
      "i" (guest_off + offset_of!(GuestState, r14)),
      "i" (guest_off + offset_of!(GuestState, r15))
    : "cc", "memory",
      "rax", "rbx", "rcx", "rdx", "rdi", "rsi"
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    : "intel", "volatile");

    Ok(())
}
