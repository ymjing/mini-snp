use kvm_bindings::KVMIO;
use kvm_ioctls::VmFd;
use std::os::raw::c_ulong;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::ioctl_with_mut_ptr;

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

// Manually define the ioctl number construction to avoid macro issues.
// Based on vmm-sys-util's implementation.
const IOC_READ: u32 = 2;
const IOC_WRITE: u32 = 1;
const IOC_SIZE_SHIFT: u32 = 16;
const IOC_DIR_SHIFT: u32 = 30;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> c_ulong {
    ((dir << IOC_DIR_SHIFT) | (ty << 8) | (nr << 0) | (size << IOC_SIZE_SHIFT)) as c_ulong
}

const fn iowr(ty: u32, nr: u32, size: usize) -> c_ulong {
    ioc(IOC_READ | IOC_WRITE, ty, nr, size as u32)
}

const KVM_TDX_COMMAND_NR: u8 = 0xc1;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct kvm_tdx_cmd {
    pub id: u64,
    pub data: u64,
    pub error: u32,
    pub flags: u32,
    pub reserved: [u64; 2],
}

const KVM_TDX_COMMAND: c_ulong = iowr(
    KVMIO as u32,
    KVM_TDX_COMMAND_NR as u32,
    std::mem::size_of::<kvm_tdx_cmd>(),
);

const KVM_TDX_INIT_VM: u64 = 1;
const KVM_TDX_FINALIZE_VM: u64 = 4;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct KvmTdxInitVm {
    pub attributes: u64,
    pub tdx_info_level: u32,
    pub reserved: [u32; 7],
}

#[derive(Debug)]
pub struct Tdx {}

impl Tdx {
    pub(crate) fn new() -> Result<Self> {
        Ok(Tdx {})
    }

    pub(crate) fn init_vm(&self, vm: &VmFd) -> Result<()> {
        let mut init_vm_data = KvmTdxInitVm::default();
        let mut cmd = kvm_tdx_cmd {
            id: KVM_TDX_INIT_VM,
            data: &mut init_vm_data as *mut _ as u64,
            ..Default::default()
        };

        let ret = unsafe { ioctl_with_mut_ptr(vm, KVM_TDX_COMMAND, &mut cmd) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        if cmd.error != 0 {
            return Err(errno::Error::new(cmd.error as i32));
        }
        Ok(())
    }

    pub(crate) fn finalize_vm(&self, vm: &VmFd) -> Result<()> {
        let mut cmd = kvm_tdx_cmd {
            id: KVM_TDX_FINALIZE_VM,
            ..Default::default()
        };

        let ret = unsafe { ioctl_with_mut_ptr(vm, KVM_TDX_COMMAND, &mut cmd) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        if cmd.error != 0 {
            return Err(errno::Error::new(cmd.error as i32));
        }
        Ok(())
    }
}
