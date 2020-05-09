use raw_cpuid::CpuId;

mod guest;
mod msr;
mod structs;
mod vcpu;
mod vmcs;
mod epage_table;

pub use guest::Guest;
pub use vcpu::Vcpu;
pub use epage_table::{EPageTable, EPageTableHandler};

pub fn check_hypervisor_feature() -> bool {
    if let Some(feature) = CpuId::new().get_feature_info() {
        feature.has_vmx()
    } else {
        false
    }
}
