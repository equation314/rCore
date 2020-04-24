//! The guest within the hypervisor.

use super::vmm::VMM_STATE;
use crate::rvm::RvmResult;

/// Represents a guest within the hypervisor.
#[derive(Debug)]
pub struct Guest {
    _phsy_mem_size: usize,
}

impl Guest {
    pub fn new(phsy_mem_size: usize) -> RvmResult<Self> {
        VMM_STATE.lock().alloc()?;
        Ok(Self {
            _phsy_mem_size: phsy_mem_size,
        })
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        println!("Guest free {:#x?}", self);
        VMM_STATE.lock().free();
    }
}
