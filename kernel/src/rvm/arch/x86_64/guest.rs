//! The guest within the hypervisor.

use alloc::boxed::Box;
use alloc::sync::Arc;

use super::epage_table::EPageTable;
use super::structs::VMM_STATE;
use crate::memory::GlobalFrameAlloc;
use crate::rvm::RvmResult;
use rcore_memory::VirtAddr;

/// Represents a guest within the hypervisor.
#[derive(Debug)]
pub struct Guest {
    _phsy_mem_size: usize,
    epage_table: Arc<Box<EPageTable<GlobalFrameAlloc>>>,
}

impl Guest {
    pub fn new(
        phsy_mem_size: usize,
        epage_table: Arc<Box<EPageTable<GlobalFrameAlloc>>>,
    ) -> RvmResult<Box<Self>> {
        VMM_STATE.lock().alloc()?;
        Ok(Box::new(Self {
            _phsy_mem_size: phsy_mem_size,
            epage_table,
        }))
    }

    pub fn access_guest_memory(&self) -> VirtAddr {
        self.epage_table.vmm_vaddr()
    }

    pub fn eptp(&self) -> usize {
        self.epage_table.eptp()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        println!("Guest free {:#x?}", self);
        VMM_STATE.lock().free();
    }
}
