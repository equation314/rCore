//! Implement INode for Rcore Virtual Machine

use alloc::{collections::BTreeMap, sync::Arc};
use core::any::Any;
use spin::RwLock;

use rcore_fs::vfs::*;

use super::arch::{self, Guest, Vcpu};

const RVM_IO: u32 = 0xAE00;
const RVM_GUEST_CREATE: u32 = RVM_IO + 0x01;
const RVM_VCPU_CREATE: u32 = RVM_IO + 0x11;
const RVM_VCPU_RESUME: u32 = RVM_IO + 0x12;

pub struct RvmINode {
    guests: RwLock<BTreeMap<usize, Arc<RwLock<Guest>>>>,
    vcpus: RwLock<BTreeMap<usize, Arc<RwLock<Vcpu>>>>,
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
        info!("RVM: ioctl {:#x} {:#x}", cmd, data);
        match cmd {
            RVM_GUEST_CREATE => {
                let phsy_mem_size = data;
                if arch::check_hypervisor_feature() {
                    let guest = Guest::new(phsy_mem_size)?;
                    let vmid = self.add_guest(guest);
                    Ok(vmid)
                } else {
                    warn!("RVM: no hardware support");
                    Err(FsError::NotSupported)
                }
            }
            RVM_VCPU_CREATE => {
                let vmid = data;
                if let Some(guest) = self.guests.read().get(&vmid) {
                    let vcpu = Vcpu::new(Arc::downgrade(&guest));
                    let vpid = self.add_vcpu(vcpu);
                    Ok(vpid)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_RESUME => {
                let vpid = data;
                if let Some(vcpu) = self.vcpus.read().get(&vpid) {
                    vcpu.write().resume();
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            _ => {
                warn!("RVM: invalid ioctl number");
                Err(FsError::InvalidParam)
            }
        }
    }
    fn mmap(&self, area: MMapArea) -> Result<()> {
        info!("RVM: mmap {:#x?}", area);
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

    pub fn add_guest(&self, guest: Guest) -> usize {
        let vmid = self.get_free_vmid();
        self.guests
            .write()
            .insert(vmid, Arc::new(RwLock::new(guest)));
        vmid
    }

    fn get_free_vpid(&self) -> usize {
        (0..).find(|i| !self.vcpus.read().contains_key(i)).unwrap()
    }

    pub fn add_vcpu(&self, vcpu: Vcpu) -> usize {
        let vpid = self.get_free_vpid();
        self.vcpus.write().insert(vpid, Arc::new(RwLock::new(vcpu)));
        vpid
    }

    // TODO: remove guest & vcpu
}
