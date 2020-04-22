//! Rcore Virtual Machine

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;
mod inode;

type RvmError = rcore_fs::vfs::FsError;
type RvmResult<T> = rcore_fs::vfs::Result<T>;

pub use inode::RvmINode;
