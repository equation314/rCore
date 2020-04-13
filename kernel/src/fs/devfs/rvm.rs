//! Implement INode for Rcore Virtual Machine

use core::any::Any;

use rcore_fs::vfs::*;

#[derive(Default)]
pub struct RvmINode;

impl INode for RvmINode {
    fn read_at(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize> {
        Err(FsError::NotSupported)
    }
    fn write_at(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        Err(FsError::NotSupported)
    }
    fn poll(&self) -> Result<PollStatus> {
        Ok(PollStatus {
            read: false,
            write: false,
            error: false,
        })
    }
    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            dev: 0,
            inode: 0,
            size: 0,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::CharDevice,
            mode: 0o660,
            nlinks: 1,
            uid: 0,
            gid: 0,
            rdev: make_rdev(10, 232), // misc major, kvm minor
        })
    }
    fn io_control(&self, cmd: u32, data: usize) -> Result<()> {
        info!("RVM: ioctl {:?} {:?}", cmd, data);
        Err(FsError::NotSupported)
    }
    fn mmap(&self, area: MMapArea) -> Result<()> {
        info!("RVM: mmap [{:?}, {:?})", area.start_vaddr, area.end_vaddr);
        Err(FsError::NotSupported)
    }
    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}
