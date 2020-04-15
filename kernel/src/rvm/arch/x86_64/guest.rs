pub struct Guest {
    _phsy_mem_size: usize,
}

impl Guest {
    pub fn new(phsy_mem_size: usize) -> Self {
        Self {
            _phsy_mem_size: phsy_mem_size,
        }
    }
}
