use super::vmm::VMM_STATE;
use crate::rvm::RvmResult;

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
        VMM_STATE.lock().free();
    }
}
