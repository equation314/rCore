//! Implement INode for Rcore Virtual Machine

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::any::Any;
use spin::RwLock;

use rcore_fs::vfs::*;

use super::arch::{self, Guest, Vcpu};
use crate::memory::copy_from_user;

const MAX_GUEST_NUM: usize = 64;
const MAX_VCPU_NUM: usize = 64;

const RVM_IO: u32 = 0xAE00;
const RVM_GUEST_CREATE: u32 = RVM_IO + 0x01;
const RVM_VCPU_CREATE: u32 = RVM_IO + 0x11;
const RVM_VCPU_RESUME: u32 = RVM_IO + 0x12;

pub struct RvmINode {
    guests: RwLock<BTreeMap<usize, Arc<Box<Guest>>>>,
    vcpus: RwLock<BTreeMap<usize, Box<Vcpu>>>,
}

#[repr(C)]
#[derive(Debug)]
struct RvmVcpuCreateArgs {
    vmid: u16,
    entry: u64,
}

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
    fn io_control(&self, cmd: u32, data: usize) -> Result<usize> {
        match cmd {
            RVM_GUEST_CREATE => {
                let phsy_mem_size = data;
                info!("[RVM] ioctl RVM_GUEST_CREATE {:#x}", phsy_mem_size);
                if arch::check_hypervisor_feature() {
                    let vmid = self.get_free_vmid();
                    if vmid >= MAX_GUEST_NUM {
                        warn!("[RVM] to many guests ({})", MAX_GUEST_NUM);
                        return Err(FsError::NoDeviceSpace);
                    }
                    let guest = Guest::new(phsy_mem_size)?;
                    assert!(self.add_guest(guest) == vmid);
                    Ok(vmid)
                } else {
                    warn!("[RVM] no hardware support");
                    Err(FsError::NotSupported)
                }
            }
            RVM_VCPU_CREATE => {
                let args = copy_from_user(data as *const RvmVcpuCreateArgs)
                    .ok_or(FsError::InvalidParam)?;
                let vmid = args.vmid as usize;
                info!("[RVM] ioctl RVM_VCPU_CREATE {:x?}", args);
                if let Some(guest) = self.guests.read().get(&vmid) {
                    let vpid = self.get_free_vpid();
                    if vpid >= MAX_VCPU_NUM {
                        warn!("[RVM] to many vcpus ({})", MAX_VCPU_NUM);
                        return Err(FsError::NoDeviceSpace);
                    }
                    let mut vcpu = Vcpu::new(vpid as u16, Arc::downgrade(guest))?;
                    vcpu.init(args.entry)?;
                    assert!(self.add_vcpu(vcpu) == vpid);
                    Ok(vpid)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_RESUME => {
                let vpid = data;
                info!("[RVM] ioctl RVM_VCPU_RESUME {:#x}", vpid);
                if let Some(vcpu) = self.vcpus.write().get_mut(&vpid) {
                    vcpu.resume();
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            _ => {
                warn!("[RVM] invalid ioctl number {:#x}", cmd);
                Err(FsError::InvalidParam)
            }
        }
    }
    fn mmap(&self, area: MMapArea) -> Result<()> {
        info!("[RVM] mmap {:x?}", area);
        Err(FsError::NotSupported)
    }
    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}

impl RvmINode {
    pub fn new() -> Self {
        Self {
            guests: RwLock::new(BTreeMap::new()),
            vcpus: RwLock::new(BTreeMap::new()),
        }
    }

    fn get_free_vmid(&self) -> usize {
        (0..).find(|i| !self.guests.read().contains_key(i)).unwrap()
    }

    fn add_guest(&self, guest: Box<Guest>) -> usize {
        let vmid = self.get_free_vmid();
        self.guests.write().insert(vmid, Arc::new(guest));
        vmid
    }

    fn get_free_vpid(&self) -> usize {
        (0..).find(|i| !self.vcpus.read().contains_key(i)).unwrap()
    }

    fn add_vcpu(&self, vcpu: Box<Vcpu>) -> usize {
        let vpid = self.get_free_vpid();
        self.vcpus.write().insert(vpid, vcpu);
        vpid
    }

    // TODO: remove guest & vcpu
}
