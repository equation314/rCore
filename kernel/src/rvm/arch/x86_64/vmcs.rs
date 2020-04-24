//! Virtual Machine Control Structures

use x86_64::{instructions::vmx, PhysAddr};

use crate::arch::interrupt;
use crate::rvm::{RvmError, RvmResult};

/// 16-Bit Fields
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsField16 {
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    POSTED_INTR_NV = 0x00000002,
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    GUEST_INTR_STATUS = 0x00000810,
    GUEST_PML_INDEX = 0x00000812,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
}

/// 64-Bit Fields
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsField64 {
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    PML_ADDRESS = 0x0000200e,
    PML_ADDRESS_HIGH = 0x0000200f,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    APIC_ACCESS_ADDR = 0x00002014,
    APIC_ACCESS_ADDR_HIGH = 0x00002015,
    POSTED_INTR_DESC_ADDR = 0x00002016,
    POSTED_INTR_DESC_ADDR_HIGH = 0x00002017,
    VM_FUNCTION_CONTROL = 0x00002018,
    VM_FUNCTION_CONTROL_HIGH = 0x00002019,
    EPT_POINTER = 0x0000201a,
    EPT_POINTER_HIGH = 0x0000201b,
    EOI_EXIT_BITMAP0 = 0x0000201c,
    EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
    EOI_EXIT_BITMAP1 = 0x0000201e,
    EOI_EXIT_BITMAP1_HIGH = 0x0000201f,
    EOI_EXIT_BITMAP2 = 0x00002020,
    EOI_EXIT_BITMAP2_HIGH = 0x00002021,
    EOI_EXIT_BITMAP3 = 0x00002022,
    EOI_EXIT_BITMAP3_HIGH = 0x00002023,
    EPTP_LIST_ADDRESS = 0x00002024,
    EPTP_LIST_ADDRESS_HIGH = 0x00002025,
    VMREAD_BITMAP = 0x00002026,
    VMWRITE_BITMAP = 0x00002028,
    XSS_EXIT_BITMAP = 0x0000202C,
    XSS_EXIT_BITMAP_HIGH = 0x0000202D,
    TSC_MULTIPLIER = 0x00002032,
    TSC_MULTIPLIER_HIGH = 0x00002033,
    GUEST_PHYSICAL_ADDRESS = 0x00002400,
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
    GUEST_IA32_PAT = 0x00002804,
    GUEST_IA32_PAT_HIGH = 0x00002805,
    GUEST_IA32_EFER = 0x00002806,
    GUEST_IA32_EFER_HIGH = 0x00002807,
    GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
    GUEST_PDPTR0 = 0x0000280a,
    GUEST_PDPTR0_HIGH = 0x0000280b,
    GUEST_PDPTR1 = 0x0000280c,
    GUEST_PDPTR1_HIGH = 0x0000280d,
    GUEST_PDPTR2 = 0x0000280e,
    GUEST_PDPTR2_HIGH = 0x0000280f,
    GUEST_PDPTR3 = 0x00002810,
    GUEST_PDPTR3_HIGH = 0x00002811,
    GUEST_BNDCFGS = 0x00002812,
    GUEST_BNDCFGS_HIGH = 0x00002813,
    HOST_IA32_PAT = 0x00002c00,
    HOST_IA32_PAT_HIGH = 0x00002c01,
    HOST_IA32_EFER = 0x00002c02,
    HOST_IA32_EFER_HIGH = 0x00002c03,
    HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
}

/// 32-Bit Fields
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsField32 {
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SYSENTER_CS = 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
    HOST_IA32_SYSENTER_CS = 0x00004c00,
}

/// Natural-Width Fields
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsFieldXX {
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
}

/// Loads a VMCS within a given scope.
#[derive(Debug)]
pub struct AutoVmcs {
    vmcs_paddr: u64,
    interrupt_flags: usize,
}

impl AutoVmcs {
    pub fn new(phys_addr: PhysAddr) -> RvmResult<Self> {
        unsafe {
            let interrupt_flags = interrupt::disable_and_store();
            vmx::vmptrld(phys_addr).ok_or(RvmError::DeviceError)?;
            Ok(Self {
                vmcs_paddr: phys_addr.as_u64(),
                interrupt_flags,
            })
        }
    }

    pub fn invalidate(&mut self) {
        self.vmcs_paddr = 0;
    }

    pub fn read16(&self, field: VmcsField16) -> u16 {
        self.read(field as usize) as u16
    }

    pub fn read32(&self, field: VmcsField32) -> u32 {
        self.read(field as usize) as u32
    }

    pub fn read64(&self, field: VmcsField64) -> u64 {
        #[cfg(target_pointer_width = "64")]
        return self.read(field as usize) as u64;
        #[cfg(target_pointer_width = "32")]
        return self.read(field as usize) as u64 | (self.read(field as usize + 1) as u64) << 32;
    }

    #[allow(non_snake_case)]
    pub fn readXX(&self, field: VmcsFieldXX) -> usize {
        self.read(field as usize)
    }

    pub fn write16(&mut self, field: VmcsField16, value: u16) {
        self.write(field as usize, value as usize);
    }

    pub fn write32(&mut self, field: VmcsField32, value: u32) {
        self.write(field as usize, value as usize);
    }

    pub fn write64(&mut self, field: VmcsField64, value: u64) {
        self.write(field as usize, value as usize);
        #[cfg(target_pointer_width = "32")]
        self.write(field as usize + 1, (value >> 32) as usize);
    }

    #[allow(non_snake_case)]
    pub fn writeXX(&mut self, field: VmcsFieldXX, value: usize) {
        self.write(field as usize, value);
    }

    #[inline]
    fn read(&self, field: usize) -> usize {
        debug_assert!(self.vmcs_paddr != 0);
        unsafe {
            vmx::vmread(field).unwrap_or_else(|| {
                panic!("[RVM]: vmread error: field={:#x}", field);
            })
        }
    }

    #[inline]
    fn write(&mut self, field: usize, value: usize) {
        debug_assert!(self.vmcs_paddr != 0);
        unsafe {
            if vmx::vmwrite(field, value).is_none() {
                warn!(
                    "[RVM]: vmwrite error: field={:#x}, value={:#x}",
                    field, value
                );
            }
        }
    }
}

impl Drop for AutoVmcs {
    fn drop(&mut self) {
        println!("AutoVmcs free {:#x?}", self);
        unsafe { interrupt::restore(self.interrupt_flags) };
    }
}
