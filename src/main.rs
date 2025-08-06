mod snp;
mod tdx;

use anyhow::bail;
use kvm_bindings::{
    kvm_create_guest_memfd, kvm_memory_attributes, kvm_userspace_memory_region2,
    KVM_MEMORY_ATTRIBUTE_PRIVATE, KVM_MEM_GUEST_MEMFD,
};
use kvm_ioctls::{Kvm, VcpuExit, VmFd};
use libc::{c_void, MAP_ANONYMOUS, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE};
use std::env;

const CODE: &[u8] = &[
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8, /* add %bl, %al */
    0x04, b'0', /* add $'0', %al */
    0xf4, /* hlt */
];

const CODE_MEMORY_BASE: u64 = 0x1000;
const CODE_MEMORY_SIZE: usize = 0x1000;

const KVM_X86_SNP_VM: u32 = 4;
const KVM_X86_TDX_VM: u32 = 5;

enum TeeType {
    Snp,
    Tdx,
}

fn snp_flow(vm: &VmFd) -> anyhow::Result<()> {
    // Create per-VM SNP context
    let snp = crate::snp::Snp::new()?;
    snp.init2(&vm)?;

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;

    // KVM_CREATE_GUEST_MEMFD
    let gmem = kvm_create_guest_memfd {
        size: CODE_MEMORY_SIZE as _,
        ..Default::default()
    };
    let mem_fd = vm.create_guest_memfd(gmem)?;

    // KVM_SEV_SNP_LAUNCH_START
    snp.launch_start(&vm)?;

    let hva = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            CODE_MEMORY_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    unsafe {
        libc::memset(hva, 0xcc, CODE_MEMORY_SIZE);
        libc::memcpy(hva, CODE.as_ptr() as *const c_void, CODE.len());
    }

    // KVM_SET_USER_MEMORY_REGION2
    let mem_region = kvm_userspace_memory_region2 {
        slot: 0,
        guest_phys_addr: CODE_MEMORY_BASE,
        memory_size: CODE_MEMORY_SIZE as _,
        userspace_addr: hva as _,
        guest_memfd: mem_fd as _,
        guest_memfd_offset: 0,
        flags: KVM_MEM_GUEST_MEMFD,
        ..Default::default()
    };
    unsafe { vm.set_user_memory_region2(mem_region)? };

    // KVM_SET_MEMORY_ATTRIBUTES
    let mem_attibutes = kvm_memory_attributes {
        address: CODE_MEMORY_BASE,
        size: CODE_MEMORY_SIZE as _,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as _,
        ..Default::default()
    };
    vm.set_memory_attributes(mem_attibutes)?;

    // KVM_SEV_SNP_LAUNCH_UPDATE
    snp.launch_update(
        &vm,
        hva as _,
        CODE_MEMORY_SIZE as _,
        CODE_MEMORY_BASE as _,
        1, // KVM_SEV_SNP_PAGE_TYPE_NORMAL
    )?;

    // Set vCPU registers
    let mut vcpu_sregs = vcpu.get_sregs()?;
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs)?;

    let mut vcpu_regs = vcpu.get_regs()?;
    vcpu_regs.rip = CODE_MEMORY_BASE;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 2;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs)?;

    // KVM_SEV_SNP_LAUNCH_FINISH
    snp.launch_finish(&vm)?;

    // Run the loop
    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                eprintln!("Received Halt");
                break;
            }
            r => bail!("Unexpected exit reason: {:?}", r),
        }
    }
    Ok(())
}

fn tdx_flow(vm: &VmFd) -> anyhow::Result<()> {
    // Create per-VM TDX context
    let tdx = crate::tdx::Tdx::new()?;
    tdx.init_vm(&vm)?;

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;

    // KVM_CREATE_GUEST_MEMFD
    let gmem = kvm_create_guest_memfd {
        size: CODE_MEMORY_SIZE as _,
        ..Default::default()
    };
    let mem_fd = vm.create_guest_memfd(gmem)?;

    let hva = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            CODE_MEMORY_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    unsafe {
        libc::memset(hva, 0xcc, CODE_MEMORY_SIZE);
        libc::memcpy(hva, CODE.as_ptr() as *const c_void, CODE.len());
    }

    // KVM_SET_USER_MEMORY_REGION2
    let mem_region = kvm_userspace_memory_region2 {
        slot: 0,
        guest_phys_addr: CODE_MEMORY_BASE,
        memory_size: CODE_MEMORY_SIZE as _,
        userspace_addr: hva as _,
        guest_memfd: mem_fd as _,
        guest_memfd_offset: 0,
        flags: KVM_MEM_GUEST_MEMFD,
        ..Default::default()
    };
    unsafe { vm.set_user_memory_region2(mem_region)? };

    // KVM_SET_MEMORY_ATTRIBUTES
    let mem_attibutes = kvm_memory_attributes {
        address: CODE_MEMORY_BASE,
        size: CODE_MEMORY_SIZE as _,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as _,
        ..Default::default()
    };
    vm.set_memory_attributes(mem_attibutes)?;

    // Set vCPU registers
    let mut vcpu_sregs = vcpu.get_sregs()?;
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs)?;

    let mut vcpu_regs = vcpu.get_regs()?;
    vcpu_regs.rip = CODE_MEMORY_BASE;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 2;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs)?;

    // KVM_TDX_FINALIZE_VM
    tdx.finalize_vm(&vm)?;

    // Run the loop
    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                eprintln!("Received Halt");
                break;
            }
            r => bail!("Unexpected exit reason: {:?}", r),
        }
    }
    Ok(())
}

// Runs a minimal "kernel" in 16-bit real mode.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "--tee-type" {
        eprintln!("Usage: {} --tee-type [snp|tdx]", args[0]);
        bail!("Invalid arguments");
    }

    let tee_type = match args[2].as_str() {
        "snp" => TeeType::Snp,
        "tdx" => TeeType::Tdx,
        _ => {
            eprintln!("Usage: {} --tee-type [snp|tdx]", args[0]);
            bail!("Invalid TEE type");
        }
    };

    // Open Kvm
    let kvm = Kvm::new()?;

    // Create VM
    let vm_type = match tee_type {
        TeeType::Snp => KVM_X86_SNP_VM,
        TeeType::Tdx => KVM_X86_TDX_VM,
    };
    let vm = kvm.create_vm_with_type(vm_type.into())?;

    match tee_type {
        TeeType::Snp => snp_flow(&vm),
        TeeType::Tdx => tdx_flow(&vm),
    }
}
