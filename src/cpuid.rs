use std::iter::zip;

use kvm_bindings::{kvm_cpuid2, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::VcpuFd;
use libc::c_void;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(C)]
#[derive(Debug, Clone, FromZeroes, FromBytes, AsBytes)]
pub(crate) struct SnpCpuidInfo {
    pub count: u32,
    pub _reserved1: u32,
    pub _reserved2: u64,
    pub entries: [SnpCpuidFunc; 64],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, FromZeroes, FromBytes, AsBytes)]
pub struct SnpCpuidFunc {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub xcr0_in: u64,
    pub xss_in: u64,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub reserved: u64,
}

pub(crate) fn populate_cpuid_page(
    vcpu: &VcpuFd,
    hva: *mut c_void,
    size: usize,
) -> anyhow::Result<()> {
    let mut cpuid_table = SnpCpuidInfo::new_zeroed();

    assert!(size > size_of::<SnpCpuidInfo>());

    let cpu_entries: vmm_sys_util::fam::FamStructWrapper<kvm_cpuid2> =
        vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?;

    for (src, dst) in zip(
        cpu_entries.as_slice().iter(),
        cpuid_table.entries.iter_mut(),
    ) {
        dst.eax_in = src.function;
        dst.ecx_in = src.index;
        dst.eax = src.eax;
        dst.ebx = src.ebx;
        dst.ecx = src.ecx;
        dst.edx = src.edx;
        if dst.eax_in == 0xd && (dst.ecx_in == 0x0 || dst.ecx_in == 0x1) {
            dst.ebx = 0x240;
            dst.xcr0_in = 1;
            dst.xss_in = 0;
        }
    }

    unsafe {
        libc::memset(hva, 0, size);
        libc::memcpy(
            hva,
            &cpuid_table as *const SnpCpuidInfo as *const c_void,
            size_of::<SnpCpuidInfo>(),
        );
    }

    Ok(())
}
