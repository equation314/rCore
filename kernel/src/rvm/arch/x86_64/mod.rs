use raw_cpuid::CpuId;

mod epage_table;
mod guest;
mod msr;
mod structs;
mod vcpu;
mod vmcs;
mod vmexit;

pub use epage_table::{EPageTable, EPageTableHandler};
pub use guest::Guest;
pub use vcpu::Vcpu;

pub fn check_hypervisor_feature() -> bool {
    if let Some(feature) = CpuId::new().get_feature_info() {
        feature.has_vmx()
    } else {
        false
    }
}
