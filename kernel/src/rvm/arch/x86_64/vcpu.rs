use alloc::sync::Weak;
use spin::RwLock;

use super::Guest;

pub struct Vcpu {
    _guest: Weak<RwLock<Guest>>,
}

impl Vcpu {
    pub fn new(guest: Weak<RwLock<Guest>>) -> Self {
        Self { _guest: guest }
    }

    pub fn resume(&mut self) {}
}
