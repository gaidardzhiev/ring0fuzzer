# CPU Instruction Fuzzer Kernel Module

Take your `x86_64` CPU to the edge by fuzzing raw instructions deep in ring 0, no user space hand holding here. This isn’t a playground toy; it’s a serious kernel module designed to smash undocumented CPU instructions and test the limits of your processor’s fault tolerance.

**Features at a glance:**

- Generate and execute randomized junk instructions on the CPU, then observe whether it crashes, faults, or surprisingly survives.
- Save and restore every CPU register meticulously before and after execution to keep the kernel rock solid.
- Trap faults like invalid opcode (#UD), general protection (#GP), and page faults (#PF) and handle them gracefully.
- Manage MSRs carefully to avoid bringing your CPU state into chaos.
- Keep kernel space logs for detailed post mortem without flooding dmesg.
- Control fuzzing via a user space character device interface ditch the pointless dmesg yelling.
- Built in watchdog timers to keep your system from freezing on bad instruction blasts.

## What it Does

- Generates short instruction sequences either randomly or incrementally.
- Executes these sequences safely inside the kernel with full CPU state restoration.
- Captures and classifies CPU faults immediately for clean recovery.
- Logs execution results with precise timestamps, fault status, and full register dumps.
- Exposes a minimal character device for user space control and real time log access.

## Design Notes

- Faults are intercepted via a die notifier hooked into kernel exception handling for recovery without panics.
- Per CPU executable memory allocations isolate fuzz runs and increase safety.
- Runs fuzzing workload inside a dedicated kernel thread to avoid disrupting system operations.
- Resource conscious implementation designed for minimal performance impact.
- Intended as a robust testbed for CPU instruction behavior research and kernel robustness validation.


## Usage

### Build and Install

```
make
sudo make install
sudo depmod -a
sudo modprobe fuzzer
```

### Control Commands (using `ioctl`)

Control the fuzzing process by opening `/dev/cpu_fuzzer` and issuing IOCTL commands.

- `FUZZ_IOCTL_START` – Start fuzzing.
- `FUZZ_IOCTL_STOP` – Stop fuzzing.
- `FUZZ_IOCTL_STATUS` – Query running status (returns 1 for running, 0 for stopped).

A small C program `ioctl.c` is provided for basic start, status, and stop control.
Alternatively, these IOCTL commands can be invoked from other languages or ioctl wrappers.

### Reading Logs

Read fuzz execution results from `/dev/cpu_fuzzer`. The device outputs a binary stream of fixed size records with detailed info: timestamps, status, instruction bytes, faults, and CPU registers.

Use the provided `watch.sh` shell script to decode and monitor logs in real time:

```
./watch.sh /dev/cpu_fuzzer
```

This script repeatedly reads binary records, parses fields, and prints concise human readable summaries.

## Parameters

Module parameters exposed via sysfs or at load time:

- `max_iterations`    (ulong): Maximum fuzz iterations (default 0 = unlimited).
- `fuzz_timeout_ms`   (uint) : Execution timeout per instruction in ms (default 250).
- `fuzz_random`       (bool) : Enable random instruction generation (default true).

## Files Provided

- `fuzzer.c`: Kernel module source.
- `Makefile`: Kernel module build rules.
- `setup.sh`: Convenience script to build, install, and load the module.
- `watch.sh`: Script to monitor and decode fuzz logs.
- `ioctl.c` : Example user space program to control fuzzing via ioctl.

---

## License

This project is provided under the GPL2 License.

---
