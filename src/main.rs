mod cpuid;
mod snp;

use std::os::fd::AsRawFd;

use anyhow::bail;
use kvm_bindings::{
    kvm_create_guest_memfd, kvm_enc_region, kvm_memory_attributes, kvm_sev_guest_status,
    kvm_userspace_memory_region2, KVM_MAX_CPUID_ENTRIES, KVM_MEMORY_ATTRIBUTE_PRIVATE,
    KVM_MEM_GUEST_MEMFD,
};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VmFd};
use libc::{c_void, MAP_ANONYMOUS, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE};

use crate::cpuid::populate_cpuid_page;
use crate::snp::Snp;

const KVM_SEV_SNP_PAGE_TYPE_NORMAL: u8 = 0x1;
const KVM_SEV_SNP_PAGE_TYPE_SECRETS: u8 = 0x5;
const KVM_SEV_SNP_PAGE_TYPE_CPUID: u8 = 0x6;

const CODE: &[u8] = &[
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8, /* add %bl, %al */
    0x04, b'0', /* add $'0', %al */
    0xee, /* out %al, (%dx) */
    0xb0, b'\n', /* mov $'\n', %al */
    0xee,  /* out %al, (%dx) */
    0xf4,  /* hlt */
];

const CODE_MEMORY_BASE: u64 = 0x1000;
const CODE_MEMORY_SIZE: usize = 0x1000;

const CPUID_MEMORY_BASE: u64 = 0x2000;
const CPUID_MEMORY_SIZE: usize = 0x1000;

const SECRET_MEMORY_BASE: u64 = 0x3000;
const SECRET_MEMORY_SIZE: usize = 0x1000;

fn map_memory(
    vm: &VmFd,
    snp: &Snp,
    slot: u32,
    gpa: u64,
    size: usize,
    page_type: u8,
) -> anyhow::Result<()> {
    let hva = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    // Load code if this is a normal page.
    if page_type == KVM_SEV_SNP_PAGE_TYPE_NORMAL {
        unsafe {
            libc::memset(hva, 0xcc, CODE_MEMORY_SIZE);
            libc::memcpy(hva, CODE.as_ptr() as *const c_void, CODE.len());
        }
    } else if page_type == KVM_SEV_SNP_PAGE_TYPE_CPUID {
        populate_cpuid_page(vm, hva, size)?;
    }

    // KVM_CREATE_GUEST_MEMFD
    let gmem = kvm_create_guest_memfd {
        size: CODE_MEMORY_SIZE as _,
        ..Default::default()
    };
    let mem_fd = vm.create_guest_memfd(gmem)?;

    eprintln!("1");

    // KVM_SET_USER_MEMORY_REGION2
    let mem_region = kvm_userspace_memory_region2 {
        slot,
        guest_phys_addr: gpa,   // gpa
        memory_size: size as _, // size
        userspace_addr: hva as _,
        guest_memfd: mem_fd.as_raw_fd() as _,
        guest_memfd_offset: 0,
        flags: KVM_MEM_GUEST_MEMFD,
        ..Default::default()
    };
    unsafe { vm.set_user_memory_region2(mem_region)? };

    eprintln!("2");

    // KVM_MEMORY_ENCRYPT_REG_REGION - FIXME: is this opional? QEMU does not invoke this.
    let mem_region = kvm_enc_region {
        addr: hva as _,  // host_va
        size: size as _, // size
    };
    vm.register_enc_memory_region(&mem_region)?;

    eprintln!("3");

    // KVM_SET_MEMORY_ATTRIBUTES
    let mem_attibutes = kvm_memory_attributes {
        address: gpa,
        size: size as _,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as _,
        ..Default::default()
    };
    vm.set_memory_attributes(mem_attibutes)?;

    eprintln!("4");

    // KVM_SEV_SNP_LAUNCH_UPDATE
    snp.launch_update(
        &vm, hva as _, size as _, // size
        gpa as _,  // gpa
        page_type,
    )?;

    eprintln!("5");

    Ok(())
}

// Runs a minimal "kernel" in 16-bit real mode.
fn main() -> anyhow::Result<()> {
    // Open Kvm
    let kvm = Kvm::new()?;
    eprintln!("KVM version: {}", kvm.get_api_version());

    // Create VM
    let vm = kvm.create_vm_with_type(0x4 /* KVM_X86_SNP_VM */)?;
    // Check extension
    if !vm.check_extension(Cap::UserMemory) {
        // We need this capability to load code into guest's mem.
        bail!("User memory capability missing!");
    }

    // Create per-VM SNP context
    let snp = crate::snp::Snp::new()?;
    snp.init2(&vm)?;

    // KVM_SEV_SNP_LAUNCH_START
    snp.launch_start(&vm)?;

    // Map shared memory for CODE
    eprintln!("Mapping NORMAL page");
    map_memory(
        &vm,
        &snp,
        0,
        CODE_MEMORY_BASE,
        CODE_MEMORY_SIZE,
        KVM_SEV_SNP_PAGE_TYPE_NORMAL,
    )?;
    eprintln!("Mapping NORMAL page - done");

    // Map shared memory for CPUID
    eprintln!("Mapping CPUID page");
    map_memory(
        &vm,
        &snp,
        1,
        CPUID_MEMORY_BASE,
        CPUID_MEMORY_SIZE,
        KVM_SEV_SNP_PAGE_TYPE_CPUID,
    )?;
    eprintln!("Mapping CPUID page - done");

    // Map shared memory for SECRET
    eprintln!("Mapping SECRETS page");
    map_memory(
        &vm,
        &snp,
        2,
        SECRET_MEMORY_BASE,
        SECRET_MEMORY_SIZE,
        KVM_SEV_SNP_PAGE_TYPE_SECRETS,
    )?;
    eprintln!("Mapping SECRETS page - done");

    // Create vCPU
    let id = 0;
    let mut vcpu = vm.create_vcpu(0)?;

    let mut cpu_entries = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?;
    for cpuid in cpu_entries.as_mut_slice().iter_mut() {
        if cpuid.function == 0x1 {
            cpuid.ebx &= 0x00ff_ffff;
            cpuid.ebx |= id << 24;
        } else if cpuid.function == 0xb {
            cpuid.edx = id;
        }
    }
    vcpu.set_cpuid2(&cpu_entries)?;

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

    eprintln!("6");

    // Get guest status
    //let mut status = kvm_sev_guest_status::default();
    //snp.get_guest_status(&vm, &mut status)?;
    //eprintln!("Guest status: {:?}", status);

    eprintln!("7");

    // Run the loop
    for _ in 0..10 {
        eprintln!("8");
        let ret = vcpu.run()?;
        eprintln!("9");
        match ret {
            VcpuExit::IoIn(addr, data) => {
                eprintln!(
                    "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::IoOut(addr, data) => {
                eprintln!(
                    "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::Hlt => {
                eprintln!("Received Halt");
                break;
            }
            r => bail!("Unexpected exit reason: {:?}", r),
        }
    }
    Ok(())
}
