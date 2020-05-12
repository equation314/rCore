// ref: https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%204%20-%20Address%20Translation%20Using%20Extended%20Page%20Table%20(EPT)/MyHypervisorDriver/MyHypervisorDriver/EPT.h

#![allow(dead_code)]

use crate::memory::phys_to_virt;
use alloc::boxed::Box;
use alloc::sync::Arc;
use rcore_memory::memory_set::handler::{FrameAllocator, MemoryHandler};
use rcore_memory::memory_set::MemoryAttr;
use rcore_memory::paging::PageTable;
use rcore_memory::PAGE_SIZE;
use rcore_memory::{PhysAddr, VirtAddr};

const MASK_PAGE_ALIGNED: usize = PAGE_SIZE - 1;

/// Extended page table
#[derive(Debug)]
pub struct EPageTable<T: FrameAllocator> {
    guest_physi_size: usize,
    guest_physi_start: usize,
    vmm_virt_start: VirtAddr,
    allocator: T,

    ept_page_root: PhysAddr,
}

impl<T: FrameAllocator> EPageTable<T> {
    /// Create a new EPageTable
    ///
    /// # Arguments
    ///     * guest_physi_size:
    ///         guest os physical memory size, unit: byte, must be 4KiB aligned
    ///     * guest_physi_start:
    ///         guest os physical memory start address, whole physical memory will be in [guest_physi_start, guest_physi_start + guest_physi_size)
    ///         guest_physi_start must be 4KiB aligned
    ///     * vmm_virt_start:
    ///         vmm's virtual memory start address that mapping guest's memory address,
    ///         that is, vmm can access guest's physical memory through vmm's virtual address [vmm_virt_start, vmm_virt_start + guest_physi_size)
    ///     * allocator: FrameAllocator
    pub fn new(
        guest_physi_size: usize,
        guest_physi_start: usize,
        vmm_virt_start: VirtAddr,
        allocator: T,
    ) -> Self {
        assert_eq!(guest_physi_size & MASK_PAGE_ALIGNED, 0);
        assert_eq!(guest_physi_start & MASK_PAGE_ALIGNED, 0);
        assert_eq!(vmm_virt_start & MASK_PAGE_ALIGNED, 0);

        let mut epage_table = Self {
            guest_physi_size,
            guest_physi_start,
            vmm_virt_start,
            allocator,
            ept_page_root: 0,
        };
        epage_table.build();
        epage_table
    }
    /// return EPT value (i.e. the physical address of root extended page table)
    pub fn eptp(&self) -> usize {
        let mut eptp = EPTP::new();
        eptp.set_dirty_and_access_enabled(true);
        eptp.set_memory_type(6);
        eptp.set_page_walk_length(3);
        eptp.set_epage_table_root(self.ept_page_root);
        return eptp.value();
    }
    pub fn vmm_vaddr(&self) -> VirtAddr {
        self.vmm_virt_start
    }

    /// return page entry, will create page table if need
    fn walk(&self, guest_pa: usize) -> EPageEntry {
        let mut page_table = self.ept_page_root;
        for level in 0..4 {
            let index = (guest_pa >> (12 + (3 - level) * 9)) & 0o777;
            let mut entry = EPageEntry::new(page_table + index * 8);
            if level == 3 {
                return entry;
            }
            if !entry.is_present() {
                let new_page = self.allocator.alloc().expect("failed to alloc frame");
                // clear all entry
                for idx in 0..512 {
                    EPageEntry::new(new_page + idx * 8).zero();
                }
                entry.set_physical_address(new_page);
                entry.set_read(true);
                entry.set_write(true);
                entry.set_execute(true);
            }
            page_table = entry.get_physical_address();
        }
        unreachable!();
    }
    fn build(&mut self) {
        assert_eq!(self.ept_page_root, 0);
        self.ept_page_root = self
            .allocator
            .alloc()
            .expect("failed to allocate ept_page_root frame");
        // clear all entry
        for idx in 0..512 {
            EPageEntry::new(self.ept_page_root + idx * 8).zero();
        }
        info!(
            "[RVM] epage_table: successed alloc ept page root 0x{:x}",
            self.ept_page_root
        );

        let mut guest_mem_start = self.guest_physi_start;
        let guest_mem_end = self.guest_physi_start + self.guest_physi_size;
        loop {
            if guest_mem_start >= guest_mem_end {
                break;
            }
            let mut entry = self.walk(guest_mem_start);
            assert!(!entry.is_present());
            let new_page = self
                .allocator
                .alloc()
                .expect("failed to alloc guest memory frame");
            entry.set_physical_address(new_page);
            entry.set_read(true);
            entry.set_write(true);
            entry.set_execute(true);
            entry.set_ept_memory_type(6);
            guest_mem_start += PAGE_SIZE;
        }
        info!("[RVM] epage_table: successed build ept");
    }
    fn unbuild_dfs(&self, page: PhysAddr, level: usize) {
        for idx in 0..512 {
            let entry = EPageEntry::new(page + idx * 8);
            if entry.is_present() {
                if level == 3 {
                    self.allocator.dealloc(entry.get_physical_address());
                } else {
                    self.unbuild_dfs(entry.get_physical_address(), level + 1);
                }
            }
        }
        self.allocator.dealloc(page);
    }
    fn unbuild(&mut self) {
        self.unbuild_dfs(self.ept_page_root, 0);
        self.ept_page_root = 0;
        info!("[RVM] epage_table: successed unbuild ept");
    }
}

impl<T: FrameAllocator> Drop for EPageTable<T> {
    fn drop(&mut self) {
        self.unbuild();
    }
}

/// used for mapping vmm's virtual memory to guest os's physical memory
#[derive(Debug, Clone)]
pub struct EPageTableHandler<T: FrameAllocator>(Arc<Box<EPageTable<T>>>);

impl<T: FrameAllocator> EPageTableHandler<T> {
    pub fn new(epage_table: Arc<Box<EPageTable<T>>>) -> Self {
        Self(epage_table)
    }
}

impl<T: FrameAllocator> MemoryHandler for EPageTableHandler<T> {
    fn box_clone(&self) -> Box<dyn MemoryHandler> {
        Box::new(self.clone())
    }

    fn map(&self, pt: &mut dyn PageTable, addr: VirtAddr, attr: &MemoryAttr) {
        assert!(
            self.0.vmm_virt_start <= addr && addr < self.0.vmm_virt_start + self.0.guest_physi_size
        );
        let guest_pa = addr - self.0.vmm_virt_start + self.0.guest_physi_start;
        let target = self.0.walk(guest_pa).get_physical_address();
        let entry = pt.map(addr, target);
        attr.apply(entry);
    }

    fn unmap(&self, pt: &mut dyn PageTable, addr: VirtAddr) {
        assert!(
            self.0.vmm_virt_start <= addr && addr < self.0.vmm_virt_start + self.0.guest_physi_size
        );
        pt.unmap(addr);
    }

    fn clone_map(
        &self,
        pt: &mut dyn PageTable,
        src_pt: &mut dyn PageTable,
        addr: VirtAddr,
        attr: &MemoryAttr,
    ) {
        // copied from ByFrame
        self.map(pt, addr, attr);
        let data = src_pt.get_page_slice_mut(addr);
        pt.get_page_slice_mut(addr).copy_from_slice(data);
    }

    fn handle_page_fault(&self, _pt: &mut dyn PageTable, _addr: VirtAddr) -> bool {
        false
    }
}

/*
struct {
    UINT64 Read : 1; // bit 0
    UINT64 Write : 1; // bit 1
    UINT64 Execute : 1; // bit 2
    UINT64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type) (last level entry only)
    UINT64 IgnorePAT : 1; // bit 6 (last level entry only)
    UINT64 Ignored1 : 1; // bit 7
    UINT64 AccessedFlag : 1; // bit 8
    UINT64 DirtyFlag : 1; // bit 9 (last level entry only)
    UINT64 ExecuteForUserMode : 1; // bit 10
    UINT64 Ignored2 : 1; // bit 11
    UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
    UINT64 Reserved : 4; // bit 51:N
    UINT64 Ignored3 : 11; // bit 62:52
    UINT64 SuppressVE : 1; // bit 63 (last level entry only)
}Fields;
*/
struct EPageEntry {
    hpaaddr: PhysAddr, // host physical addr
}

impl EPageEntry {
    fn new(hpaaddr: PhysAddr) -> Self {
        assert_eq!(PAGE_SIZE, 4096); // TODO
        Self { hpaaddr }
    }
    fn get_value(&self) -> usize {
        let va = phys_to_virt(self.hpaaddr);
        unsafe { *(va as *const usize) }
    }
    fn set_value(&mut self, value: usize) {
        let va = phys_to_virt(self.hpaaddr);
        unsafe {
            *(va as *mut usize) = value;
        };
    }
    fn get_bits(&self, s: usize, t: usize) -> usize {
        assert!(s < t && t <= 64);
        let value = self.get_value();
        (value >> s) & ((1 << (t - s)) - 1)
    }
    fn set_bits(&mut self, s: usize, t: usize, value: usize) {
        assert!(s < t && t <= 64);
        assert!(value < (1 << (t - s)));
        let old_value = self.get_value();
        self.set_value(old_value - self.get_bits(s, t) + (value << s));
    }

    fn zero(&mut self) {
        self.set_value(0);
    }
    fn is_present(&self) -> bool {
        self.get_physical_address() != 0
    }

    fn get_read(&self) -> bool {
        self.get_bits(0, 1) != 0
    }
    fn set_read(&mut self, value: bool) {
        self.set_bits(0, 1, value as usize)
    }

    fn get_write(&self) -> bool {
        self.get_bits(1, 2) != 0
    }
    fn set_write(&mut self, value: bool) {
        self.set_bits(1, 2, value as usize)
    }

    fn get_execute(&self) -> bool {
        self.get_bits(2, 3) != 0
    }
    fn set_execute(&mut self, value: bool) {
        self.set_bits(2, 3, value as usize)
    }

    fn get_ept_memory_type(&self) -> usize {
        self.get_bits(3, 6)
    }
    fn set_ept_memory_type(&mut self, value: usize) {
        self.set_bits(3, 6, value)
    }

    fn get_accessed(&self) -> bool {
        self.get_bits(8, 9) != 0
    }
    fn set_accessed(&mut self, value: bool) {
        self.set_bits(8, 9, value as usize)
    }

    fn get_dirty(&self) -> bool {
        self.get_bits(9, 10) != 0
    }
    fn set_dirty(&mut self, value: bool) {
        self.set_bits(9, 10, value as usize)
    }

    fn get_execute_for_user_mode(&self) -> bool {
        self.get_bits(10, 11) != 0
    }
    fn set_execute_for_user_mode(&mut self, value: bool) {
        self.set_bits(10, 11, value as usize)
    }

    fn get_physical_address(&self) -> PhysAddr {
        self.get_bits(12, 48) << 12
    }
    fn set_physical_address(&mut self, value: PhysAddr) {
        assert_eq!(value & MASK_PAGE_ALIGNED, 0);
        self.set_bits(12, 48, value >> 12);
    }
}

/*
struct {
    UINT64 MemoryType : 3; // bit 2:0 (0 = Uncacheable (UC) - 6 = Write - back(WB))
    UINT64 PageWalkLength : 3; // bit 5:3 (This value is 1 less than the EPT page-walk length)
    UINT64 DirtyAndAceessEnabled : 1; // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
    UINT64 Reserved1 : 5; // bit 11:7
    UINT64 PML4Address : 36;
    UINT64 Reserved2 : 16;
}Fields;
*/
struct EPTP {
    value: usize,
}

impl EPTP {
    fn new() -> Self {
        Self { value: 0 }
    }
    fn value(&self) -> usize {
        self.value
    }

    fn get_bits(&self, s: usize, t: usize) -> usize {
        assert!(s < t && t <= 64);
        (self.value >> s) & ((1 << (t - s)) - 1)
    }
    fn set_bits(&mut self, s: usize, t: usize, value: usize) {
        assert!(s < t && t <= 64);
        assert!(value < (1 << (t - s)));
        self.value = self.value - self.get_bits(s, t) + (value << s);
    }

    fn get_memory_type(&self) -> usize {
        self.get_bits(0, 3)
    }
    fn set_memory_type(&mut self, value: usize) {
        self.set_bits(0, 3, value);
    }

    fn get_page_walk_length(&self) -> usize {
        self.get_bits(3, 6)
    }
    fn set_page_walk_length(&mut self, value: usize) {
        self.set_bits(3, 6, value);
    }

    fn get_dirty_and_access_enabled(&self) -> bool {
        self.get_bits(6, 7) != 0
    }
    fn set_dirty_and_access_enabled(&mut self, value: bool) {
        self.set_bits(6, 7, value as usize);
    }

    fn get_epage_table_root(&self) -> usize {
        self.get_bits(12, 48) << 12
    }
    fn set_epage_table_root(&mut self, value: PhysAddr) {
        assert_eq!(value & MASK_PAGE_ALIGNED, 0);
        self.set_bits(12, 48, value >> 12);
    }
}
