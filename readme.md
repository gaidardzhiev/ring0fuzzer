# CPU Instruction Fuzzer Kernel Module

This is a Linux kernel module that fuzzes `x86_64` CPU instructions at ring-0 on Intel Ivy Bridge CPUs.

## What it does

- Generates short instruction sequences (random or incremental).
- Executes them safely inside the kernel.
- Catches faults like invalid opcode (#UD), general protection (#GP), and page faults (#PF).
- Saves/restores CPU state and key MSRs.
- Logs execution results with timestamp, status, and registers.
- Provides a minimal char device interface for control and logs.

## Design notes

- Faults are trapped with a die notifier and redirected for recovery.
- Uses per CPU executable memory to run instructions.
- Runs fuzzing in a dedicated kernel thread.
- Conservative on resources, minimal impact on system.
- Intended for research and testing CPU instruction behavior and kernel robustness.

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

