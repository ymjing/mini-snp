# KVM SEV-SNP Minimal Guest Demo

This project demonstrates how to run a minimal 16-bit real mode "kernel" inside a KVM (Kernel-based Virtual Machine) guest, with AMD SEV-SNP (Secure Nested Paging) enabled. SEV-SNP provides enhanced security for virtual machines by encrypting their memory and protecting them from the hypervisor.

## Project Structure

- **`src/main.rs`**: This is the main entry point of the application. It performs the following key functions:
    - Initializes KVM.
    - Creates a virtual machine with SNP enabled (`KVM_X86_SNP_VM`).
    - Initializes the SEV-SNP context for the VM using helpers from `src/snp.rs`.
    - Creates a vCPU.
    - Allocates guest memory using `kvm_create_guest_memfd` for private memory.
    - Manages the SEV-SNP launch lifecycle:
        - `KVM_SEV_SNP_LAUNCH_START`
        - Maps a small code snippet into the guest's memory.
        - `KVM_SET_USER_MEMORY_REGION2` to define the memory region.
        - `KVM_SET_MEMORY_ATTRIBUTES` to mark the memory as private.
        - `KVM_SEV_SNP_LAUNCH_UPDATE` to encrypt the memory pages.
    - Sets up the vCPU registers (`sregs` for segment registers and `regs` for general-purpose registers, including `rip` to point to the code).
    - `KVM_SEV_SNP_LAUNCH_FINISH` to finalize the guest launch.
    - Runs the vCPU loop, expecting a `VcpuExit::Hlt` when the guest code finishes.

- **`src/snp.rs`**: This module provides wrapper functions around the KVM ioctls required to manage an SEV-SNP enabled guest. It handles:
    - Opening `/dev/sev` to communicate with the AMD Secure Processor.
    - `KVM_SEV_INIT2`: Initializes the SEV firmware context.
    - `KVM_SEV_SNP_LAUNCH_START`: Initiates the SNP guest launch flow.
    - `KVM_SEV_SNP_LAUNCH_UPDATE`: Encrypts and measures guest memory pages.
    - `KVM_SEV_SNP_LAUNCH_FINISH`: Completes the SNP guest launch.

- **`CODE` constant in `src/main.rs`**: This byte array (`&[u8]`) contains a very simple 16-bit real mode program:
    ```assembly
    mov $0x3f8, %dx  ; Target I/O port (not used in SNP)
    add %bl, %al     ; Add value in BL to AL (AL = AL + BL)
    add $'0', %al     ; Convert AL to ASCII digit
    hlt              ; Halt the CPU
    ```
    In the `main` function, `rax` (which AL is part of) and `rbx` (which BL is part of) are both initialized to `2`. So, this code calculates `2 + 2 = 4`. The `add $'0', %al` would typically be used if outputting to a display, to convert the number `4` to the character `'4'`, but I/O is generally restricted in SEV-SNP guests for security, as noted by the comment `// note: I/O is not supported in SEV-SNP guests`. The primary purpose here is to have a minimal piece of executable code to demonstrate memory encryption and execution within the SNP guest.

## Building and Running

This project uses Cargo, the Rust build system and package manager.

1.  **Prerequisites**:
    *   A Linux system with KVM enabled.
    *   An AMD CPU that supports SEV-SNP.
    *   The necessary KVM and SEV kernel modules loaded.
    *   Rust and Cargo installed.
    *   Access to `/dev/kvm` and `/dev/sev`.

2.  **Build**:
    ```bash
    cargo build
    ```

3.  **Run**:
    ```bash
    sudo target/debug/kvm-sev-snp-demo 
    ```
    (Root privileges are typically required for KVM operations and accessing `/dev/sev`).

    If successful, you should see the message:
    ```
    Received Halt
    ```
    This indicates that the guest VM executed the tiny kernel and halted as expected.

## Disclaimer

This is a demonstration project and may require specific kernel versions or configurations to run successfully. It focuses on the low-level aspects of launching an SEV-SNP guest.
