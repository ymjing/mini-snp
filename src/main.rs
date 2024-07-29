use anyhow::bail;
use kvm_ioctls::{Cap, Kvm, VcpuExit};
use libc::c_void;
use libc::{MAP_ANONYMOUS, MAP_FIXED, MAP_SHARED};
use libc::{PROT_READ, PROT_WRITE};

const CODE: &[u8; 12] = &[
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8, /* add %bl, %al */
    0x04, b'0', /* add $'0', %al */
    0xee, /* out %al, (%dx) */
    0xb0, b'\n', /* mov $'\n', %al */
    0xee,  /* out %al, (%dx) */
    0xf4,  /* hlt */
];
const GUEST_MEMORY_SIZE: usize = 0x100000;
const GUEST_MEMORY_BASE: u64 = 0xFF000;
const SNP_UPDATE_ADDR: u64 = 0xDEAD0000;

fn main() -> anyhow::Result<()> {
    // 1) Open Kvm
    let kvm = Kvm::new()?;
    eprintln!("KVM version: {}", kvm.get_api_version());
    // 2) Create VM
    let vm = kvm.create_vm()?;
    // 3) Check extension
    if !vm.check_extension(Cap::UserMemory) {
        bail!("User memory capability missing!");
    }

    let guest_memory = unsafe {
        libc::mmap(
            SNP_UPDATE_ADDR as *mut libc::c_void,
            GUEST_MEMORY_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        )
    };
    unsafe {
        libc::memset(guest_memory, 0xcc, GUEST_MEMORY_SIZE);
        libc::memcpy(guest_memory, CODE.as_ptr() as *const c_void, CODE.len());
    }

    // 4) Create one bCPU
    let mut vcpu = vm.create_vcpu(0)?;

    let mut vcpu_sregs = vcpu.get_sregs()?;
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu.get_regs()?;
    vcpu_regs.rip = guest_addr;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs)?;


    loop {
        match vcpu.run()? {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::IoOut(addr, data) => {
                println!(
                    "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::Hlt => {
                break;
            }
            r => bail!("Unexpected exit reason: {:?}", r),
        }
    }
    Ok(())
}
