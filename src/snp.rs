use kvm_bindings::{kvm_memory_attributes, kvm_sev_cmd, KVMIO, KVM_MEMORY_ATTRIBUTE_PRIVATE};
use kvm_ioctls::VmFd;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::ioctl_with_mut_ptr;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iow_nr};

use std::ffi::CStr;
use std::os::fd::OwnedFd;
use std::os::fd::{AsRawFd, FromRawFd};

pub(crate) type SnpResult<T> = std::result::Result<T, errno::Error>;

const KVM_SEV_INIT2: u32 = 22;
const KVM_SEV_SNP_LAUNCH_START: u32 = 100;
const KVM_SEV_SNP_LAUNCH_UPDATE: u32 = 101;
const KVM_SEV_SNP_LAUNCH_FINISH: u32 = 102;

/// From SEV SNP Firmware ABI Specification, Revision 1.55, Table 67.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum SnpPageType {
    /// A normal data page.
    Normal = 1,
}

ioctl_iow_nr!(
    KVM_SET_MEMORY_ATTRIBUTES,
    KVMIO,
    0xd2,
    kvm_memory_attributes
);

pub(crate) fn kvm_set_private_memory(vm: &VmFd, gpa: u64, size: u64) -> SnpResult<()> {
    let mut attributes = kvm_memory_attributes {
        address: gpa,
        size: size,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as _,
        ..Default::default()
    };

    unsafe {
        let ret = ioctl_with_mut_ptr(vm, KVM_SET_MEMORY_ATTRIBUTES(), &mut attributes);
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevInit {
    pub vmsa_features: u64,
    pub flags: u32,
    pub ghcb_version: u16,
    pub pad1: u16,
    pub pad2: [u32; 8],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchStart {
    pub policy: u64,
    pub gosvw: [u8; 16],
    pub flags: u16,
    pub pad0: [u8; 6],
    pub pad1: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchUpdate {
    pub gfn_start: u64,
    pub uaddr: u64,
    pub len: u64,
    pub type_: u8,
    pub pad0: u8,
    pub flags: u16,
    pub pad1: u32,
    pub pad2: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchFinish {
    pub id_block_uaddr: u64,
    pub id_auth_uaddr: u64,
    pub id_block_en: u8,
    pub auth_key_en: u8,
    pub vcek_disabled: u8,
    pub host_data: [u8; 32],
    pub pad0: [u8; 3],
    pub flags: u16,
    pub pad1: [u64; 4],
}

#[derive(Debug)]
pub struct Snp {
    pub sev_fd: OwnedFd,
}

impl Snp {
    pub(crate) fn new() -> SnpResult<Self> {
        let sev_path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/sev\0") };
        let open_flags = libc::O_RDWR | libc::O_CLOEXEC;
        let fd = unsafe {
            libc::open(
                sev_path.as_ref().as_ptr() as *const libc::c_char,
                open_flags,
            )
        };
        if fd >= 0 {
            let sev_fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Snp { sev_fd })
        } else {
            Err(errno::Error::last())
        }
    }

    pub(crate) fn init2(&self, vm: &VmFd) -> SnpResult<()> {
        let mut init = KvmSevInit::default();
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_INIT2,
            data: &mut init as *mut KvmSevInit as _,
            sev_fd: self.sev_fd.as_raw_fd() as _,
            ..Default::default()
        };
        unsafe { vm.encrypt_op(&mut sev_cmd) }
    }

    pub(crate) fn launch_start(&self, vm: &VmFd) -> SnpResult<()> {
        // See AMD Spec Section 4.3 - Guest Policy
        // Bit 17 is reserved and has to be one.
        let policy: u64 = 0 |  // minor
            0 << 8 |  // major
            1 << 16 |  // SMT
            1 << 17 |  // MB1
            0 << 18 |  // MIGRATE_MA
            1 << 19;
        let mut start: KvmSevSnpLaunchStart = KvmSevSnpLaunchStart {
            policy,
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_START,
            data: &mut start as *mut KvmSevSnpLaunchStart as _,
            sev_fd: self.sev_fd.as_raw_fd() as _,
            ..Default::default()
        };
        unsafe { vm.encrypt_op(&mut sev_cmd) }
    }

    pub(crate) fn launch_update(
        &self,
        vm: &VmFd,
        host_va: u64,
        size: u64,
        gpa: u64,
        page_type: SnpPageType,
    ) -> SnpResult<()> {
        let mut update = KvmSevSnpLaunchUpdate {
            gfn_start: gpa >> 12,
            uaddr: host_va,
            len: size,
            type_: page_type as _,
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_UPDATE,
            data: &mut update as *mut KvmSevSnpLaunchUpdate as _,
            sev_fd: self.sev_fd.as_raw_fd() as _,
            ..Default::default()
        };
        unsafe { vm.encrypt_op(&mut sev_cmd) }
    }

    pub(crate) fn launch_finish(&self, vm: &VmFd) -> SnpResult<()> {
        let mut finish = KvmSevSnpLaunchFinish::default();
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_FINISH,
            data: &mut finish as *mut KvmSevSnpLaunchFinish as _,
            sev_fd: self.sev_fd.as_raw_fd() as _,
            ..Default::default()
        };
        unsafe { vm.encrypt_op(&mut sev_cmd) }
    }
}