//! The packet forwarded to userspace on VM Exits.

use core::fmt::{Debug, Formatter, Result};

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum RvmExitPacketKind {
    GuestIo = 1,
    GuestMmio = 2,
    GuestVcpu = 3,
}

#[repr(C)]
pub union IoValue {
    pub d_u8: u8,
    pub d_u16: u16,
    pub d_u32: u32,
    pub buf: [u8; 4],
}

#[repr(C)]
#[derive(Debug)]
pub struct IoPacket {
    pub port: u16,
    pub access_size: u8,
    pub input: bool,
    pub value: IoValue,
}

#[repr(C)]
#[derive(Debug)]
pub struct MmioPacket {
    pub addr: u64,
}

#[repr(C)]
union RvmExitPacketInnner {
    io: IoPacket,
    mmio: MmioPacket,
}

#[repr(C)]
pub struct RvmExitPacket {
    kind: RvmExitPacketKind,
    key: u64,
    inner: RvmExitPacketInnner,
}

impl Default for IoValue {
    fn default() -> Self {
        Self { d_u32: 0 }
    }
}

impl IoValue {
    pub fn from_raw_parts(data: *const u8, access_size: u8) -> Self {
        let mut buf: [u8; 4] = [0; 4];
        unsafe {
            buf[..access_size as usize]
                .copy_from_slice(core::slice::from_raw_parts(data, access_size as usize))
        }
        Self { buf }
    }
}

impl Debug for IoValue {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "IoValue {{ 0x{:08x} }}", unsafe { self.d_u32 })
    }
}

impl RvmExitPacket {
    pub fn new_io_packet(key: u64, io_packet: IoPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestIo,
            key,
            inner: RvmExitPacketInnner { io: io_packet },
        }
    }
}

impl Debug for RvmExitPacket {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut out = f.debug_struct("RvmExitPacket");
        out.field("kind", &self.kind).field("key", &self.key);
        unsafe {
            match self.kind {
                RvmExitPacketKind::GuestIo => out.field("inner", &self.inner.io),
                RvmExitPacketKind::GuestMmio => out.field("inner", &self.inner.mmio),
                _ => out.field("inner", &"Unknown"),
            };
        }
        out.finish()
    }
}
