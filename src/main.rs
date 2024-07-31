mod snp;

use anyhow::bail;
use kvm_bindings::{
    kvm_create_guest_memfd, kvm_memory_attributes, kvm_userspace_memory_region2,
    KVM_MEMORY_ATTRIBUTE_PRIVATE, KVM_MEM_GUEST_MEMFD,
};
use kvm_ioctls::{Kvm, VcpuExit};
use libc::{c_void, MAP_ANONYMOUS, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE};

const CODE: &[u8] = &[
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8, /* add %bl, %al */
    0x04, b'0', /* add $'0', %al */
    0xf4, /* hlt */
]; // note: I/O is not supported in SEV-SNP guests

const CODE_MEMORY_BASE: u64 = 0x1000;
const CODE_MEMORY_SIZE: usize = 0x1000;

// Runs a minimal "kernel" in 16-bit real mode.
fn main() -> anyhow::Result<()> {
    // Open Kvm
    let kvm = Kvm::new()?;

    // Create VM
    let vm = kvm.create_vm_with_type(0x4 /* KVM_X86_SNP_VM */)?;

    // Create per-VM SNP context
    let snp = crate::snp::Snp::new()?;
    snp.init2(&vm)?;

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?; // this has to be before LAUNCH_START

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
    let slot = 0;
    let mem_region = kvm_userspace_memory_region2 {
        slot,
        guest_phys_addr: CODE_MEMORY_BASE,  // gpa
        memory_size: CODE_MEMORY_SIZE as _, // size
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
        CODE_MEMORY_SIZE as _, // size
        CODE_MEMORY_BASE as _, // gpa
        0x1,                   // KVM_SEV_SNP_PAGE_TYPE_NORMAL
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
    snp.launch_finish(&vm)?; // this should be after vCPU set_regs

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
