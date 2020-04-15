//! Rcore Virtual Machine

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;
mod inode;

pub use inode::RvmINode;
