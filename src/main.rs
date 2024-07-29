use anyhow::bail;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Cap, Kvm, VcpuExit};
use libc::c_void;
use libc::{MAP_ANONYMOUS, MAP_FIXED, MAP_SHARED};
use libc::{PROT_READ, PROT_WRITE};

const CODE: &[u8] = &[
    0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
    0x00, 0xd8, /* add %bl, %al */
    0x04, b'0', /* add $'0', %al */
    0xee, /* out %al, (%dx) */
    0xb0, b'\n', /* mov $'\n', %al */
    0xee,  /* out %al, (%dx) */
    0xf4,  /* hlt */
];
const GUEST_MEMORY_SIZE: usize = 0x1000;
const GUEST_MEMORY_BASE: u64 = 0x1000; // 16-bit real mode;

// Runs a minimal "kernel" in 16-bit real mode.
fn main() -> anyhow::Result<()> {
    // 1) Open Kvm
    let kvm = Kvm::new()?;
    eprintln!("KVM version: {}", kvm.get_api_version());
    // 2) Create VM
    let vm = kvm.create_vm()?;
    // 3) Check extension
    if !vm.check_extension(Cap::UserMemory) {
        // We need this capability to load code into guest's mem.
        bail!("User memory capability missing!");
    }
    // 4) Load code into guest
    let load_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            GUEST_MEMORY_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        )
    };
    unsafe {
        libc::memset(load_addr, 0xcc, GUEST_MEMORY_SIZE);
        libc::memcpy(load_addr, CODE.as_ptr() as *const c_void, CODE.len());
    }


    let slot = 0;
    let mem_region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: GUEST_MEMORY_BASE,
        memory_size: GUEST_MEMORY_SIZE as u64,
        userspace_addr: load_addr as u64,
        flags: 0,
    };
    unsafe { vm.set_user_memory_region(mem_region)? };

    // 5) Create vCPU and set registers
    let mut vcpu = vm.create_vcpu(0)?;

    let mut vcpu_sregs = vcpu.get_sregs()?;
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs)?;

    let mut vcpu_regs = vcpu.get_regs()?;
    vcpu_regs.rip = GUEST_MEMORY_BASE;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs)?;

    // 6) Run
    for _ in 0..10 {
        match vcpu.run()? {
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
